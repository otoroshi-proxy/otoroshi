package otoroshi.utils.netty

import akka.stream.scaladsl.{Sink, Source}
import akka.util.ByteString
import io.netty.buffer.{ByteBuf, Unpooled}
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.channel.{Channel, ChannelHandlerContext, EventLoopGroup}
import io.netty.handler.codec.http._
import io.netty.handler.codec.http.cookie.ServerCookieDecoder
import io.netty.handler.codec.http.websocketx._
import io.netty.handler.logging.LogLevel
import io.netty.handler.ssl._
import io.netty.handler.ssl.util.SelfSignedCertificate
import io.netty.incubator.codec.quic.QuicSslContextBuilder
import io.netty.util.{CharsetUtil, ReferenceCountUtil}
import org.reactivestreams.{Processor, Publisher}
import otoroshi.env.Env
import otoroshi.next.proxy.ProxyEngine
import otoroshi.script.RequestHandler
import otoroshi.ssl.{ClientAuth, DynamicSSLEngineProvider}
import otoroshi.utils.reactive.ReactiveStreamUtils
import otoroshi.utils.syntax.implicits._
import play.api.http.websocket.Message
import play.api.http.{HttpChunk, HttpEntity, HttpRequestHandler}
import play.api.libs.crypto.CookieSignerProvider
import play.api.libs.json.Json
import play.api.libs.typedmap.TypedMap
import play.api.mvc._
import play.api.mvc.request.{Cell, RemoteConnection, RequestAttrKey, RequestTarget}
import play.api.{Configuration, Logger}
import play.core.server.common.WebSocketFlowHandler
import play.core.server.common.WebSocketFlowHandler.{MessageType, RawMessage}
import reactor.netty.http.HttpDecoderSpec
import reactor.netty.http.server.HttpServerRequest
import reactor.netty.{Connection, NettyOutbound}

import java.net.{InetAddress, URI}
import java.security.cert.X509Certificate
import java.security.{Provider, SecureRandom}
import java.util.concurrent.atomic.AtomicLong
import java.util.function.BiFunction
import javax.net.ssl._
import scala.jdk.CollectionConverters._
import scala.util.{Failure, Success, Try}

object ReactorNettyRemoteConnection {
  val logger = Logger("otoroshi-experimental-reactor-netty-server-remote-connection")
}

class ReactorNettyRemoteConnection(req: HttpServerRequest, val secure: Boolean, sessionOpt: Option[SSLSession]) extends RemoteConnection {
  lazy val remoteAddress: InetAddress = req.remoteAddress().getAddress
  lazy val clientCertificateChain: Option[Seq[X509Certificate]] = {
    if (secure) {
      sessionOpt match {
        case None =>
          ReactorNettyRemoteConnection.logger.warn(s"Something weird happened with the TLS session: it does not exists ...")
          None
        case Some(session) => {
          if (session.isValid) {
            val certs = try {
              session.getPeerCertificates.toSeq.collect { case c: X509Certificate => c }
            } catch {
              case e: SSLPeerUnverifiedException => Seq.empty[X509Certificate]
            }
            if (certs.nonEmpty) {
              Some(certs)
            } else {
              None
            }
          } else {
            None
          }
        }
      }
    } else {
      None
    }
  }
}

object NettyRemoteConnection {
  val logger = Logger("otoroshi-experimental-netty-server-remote-connection")
}

class NettyRemoteConnection(req: FullHttpRequest, ctx: ChannelHandlerContext, val secure: Boolean, sessionOpt: Option[SSLSession]) extends RemoteConnection {
  lazy val remoteAddress: InetAddress = {
    val addr = Connection.from(ctx.channel()).address().asInstanceOf[io.netty.incubator.codec.quic.QuicStreamAddress]
    // TODO: fix it
    InetAddress.getLocalHost
  }
  lazy val clientCertificateChain: Option[Seq[X509Certificate]] = {
    if (secure) {
      sessionOpt match {
        case None =>
          ReactorNettyRemoteConnection.logger.warn(s"Something weird happened with the TLS session: it does not exists ...")
          None
        case Some(session) => {
          if (session.isValid) {
            val certs = try {
              session.getPeerCertificates.toSeq.collect { case c: X509Certificate => c }
            } catch {
              case e: SSLPeerUnverifiedException => Seq.empty[X509Certificate]
            }
            if (certs.nonEmpty) {
              Some(certs)
            } else {
              None
            }
          } else {
            None
          }
        }
      }
    } else {
      None
    }
  }
}

class ReactorNettyRequestTarget(req: HttpServerRequest) extends RequestTarget {
  lazy val kUri = akka.http.scaladsl.model.Uri(uriString)
  lazy val uri: URI = new URI(uriString)
  lazy val uriString: String = req.uri()
  lazy val path: String = req.fullPath()
  lazy val queryMap: Map[String, Seq[String]] = kUri.query().toMultiMap.mapValues(_.toSeq)
}

class NettyRequestTarget(req: FullHttpRequest) extends RequestTarget {
  lazy val kUri = akka.http.scaladsl.model.Uri(uriString)
  lazy val uri: URI = new URI(uriString)
  lazy val uriString: String = req.uri()
  lazy val path: String = kUri.path.toString()
  lazy val queryMap: Map[String, Seq[String]] = kUri.query().toMultiMap.mapValues(_.toSeq)
}

object ReactorNettyRequest {
  val counter = new AtomicLong(0L)
}

object NettyRequest {
  val counter = new AtomicLong(0L)
}

class ReactorNettyRequest(req: HttpServerRequest, secure: Boolean, sessionOpt: Option[SSLSession], sessionCookieBaker: SessionCookieBaker, flashCookieBaker: FlashCookieBaker) extends ReactorNettyRequestHeader(req, secure, sessionOpt, sessionCookieBaker, flashCookieBaker) with Request[Source[ByteString, _]] {
  lazy val body: Source[ByteString, _] = {
    val flux: Publisher[ByteString] = req.receive().map { bb =>
      val builder = ByteString.newBuilder
      bb.readBytes(builder.asOutputStream, bb.readableBytes())
      builder.result()
    }
    Source.fromPublisher(flux)
  }
}

class ReactorNettyRequestHeader(req: HttpServerRequest, secure: Boolean, sessionOpt: Option[SSLSession], sessionCookieBaker: SessionCookieBaker, flashCookieBaker: FlashCookieBaker) extends RequestHeader {

  lazy val zeSession: Session = {
    Option(req.cookies().get(sessionCookieBaker.COOKIE_NAME))
      .flatMap(_.asScala.headOption)
      .flatMap { value =>
        Try(sessionCookieBaker.deserialize(sessionCookieBaker.decode(value.value()))).toOption
      }
      .getOrElse(Session())
  }
  lazy val zeFlash: Flash = {
    Option(req.cookies().get(flashCookieBaker.COOKIE_NAME))
      .flatMap(_.asScala.headOption)
      .flatMap { value =>
        Try(flashCookieBaker.deserialize(flashCookieBaker.decode(value.value()))).toOption
      }
      .getOrElse(Flash())
  }
  lazy val attrs = TypedMap.apply(
    RequestAttrKey.Id      -> ReactorNettyRequest.counter.incrementAndGet(),
    RequestAttrKey.Session -> Cell(zeSession),
    RequestAttrKey.Flash -> Cell(zeFlash),
    RequestAttrKey.Server -> "reactor-netty-experimental",
    RequestAttrKey.Cookies -> Cell(Cookies(req.cookies().asScala.toSeq.flatMap {
      case (_, cookies) => cookies.asScala.map {
        case cookie: io.netty.handler.codec.http.cookie.DefaultCookie => {
          play.api.mvc.Cookie(
            name = cookie.name(),
            value = cookie.value(),
            maxAge = Option(cookie.maxAge()).map(_.toInt),
            path = Option(cookie.path()).filter(_.nonEmpty).getOrElse("/"),
            domain = Option(cookie.domain()).filter(_.nonEmpty),
            secure = cookie.isSecure,
            httpOnly = cookie.isHttpOnly,
            sameSite = Option(cookie.sameSite()).map {
              case e if e == io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.None =>  play.api.mvc.Cookie.SameSite.None
              case e if e == io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Strict => play.api.mvc.Cookie.SameSite.Strict
              case e if e == io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Lax => play.api.mvc.Cookie.SameSite.Lax
              case _ => play.api.mvc.Cookie.SameSite.None
            }
          )
        }
        case cookie => {
          play.api.mvc.Cookie(
            name = cookie.name(),
            value = cookie.value(),
            maxAge = Option(cookie.maxAge()).map(_.toInt),
            path = Option(cookie.path()).filter(_.nonEmpty).getOrElse("/"),
            domain = Option(cookie.domain()).filter(_.nonEmpty),
            secure = cookie.isSecure,
            httpOnly = cookie.isHttpOnly,
            sameSite = None
          )
        }
      }
    }))
  )
  lazy val method: String = req.method().toString
  lazy val version: String = req.version().toString
  lazy val headers: Headers = Headers(
    (req.requestHeaders().entries().asScala.map(e => (e.getKey, e.getValue)) ++ sessionOpt.map(s => ("Tls-Session-Info", s.toString))): _*
  )
  lazy val connection: RemoteConnection = new ReactorNettyRemoteConnection(req, secure, sessionOpt)
  lazy val target: RequestTarget = new ReactorNettyRequestTarget(req)
}

class NettyRequest(req: FullHttpRequest, ctx: ChannelHandlerContext, rawBody: ByteString, secure: Boolean, sessionOpt: Option[SSLSession], sessionCookieBaker: SessionCookieBaker, flashCookieBaker: FlashCookieBaker) extends NettyRequestHeader(req, ctx, secure, sessionOpt, sessionCookieBaker, flashCookieBaker) with Request[Source[ByteString, _]] {
  lazy val body: Source[ByteString, _] = {
    // val flux: Publisher[ByteString] = req.receive().map { bb =>
    //   val builder = ByteString.newBuilder
    //   bb.readBytes(builder.asOutputStream, bb.readableBytes())
    //   builder.result()
    // }
    // Source.fromPublisher(flux)
    Source.single(rawBody)
  }
}

class NettyRequestHeader(req: FullHttpRequest, ctx: ChannelHandlerContext, secure: Boolean, sessionOpt: Option[SSLSession], sessionCookieBaker: SessionCookieBaker, flashCookieBaker: FlashCookieBaker) extends RequestHeader {

  lazy val _cookies = Option(req.headers().get("Cookie")).map(c => ServerCookieDecoder.LAX.decode(c).asScala.groupBy(_.name()).mapValues(_.toSeq)).getOrElse(Map.empty[String, Seq[io.netty.handler.codec.http.cookie.DefaultCookie]])

  lazy val zeSession: Session = {
    _cookies.get(sessionCookieBaker.COOKIE_NAME)
      .flatMap(_.headOption)
      .flatMap { value =>
        Try(sessionCookieBaker.deserialize(sessionCookieBaker.decode(value.value()))).toOption
      }
      .getOrElse(Session())
  }
  lazy val zeFlash: Flash = {
    _cookies.get(flashCookieBaker.COOKIE_NAME)
      .flatMap(_.headOption)
      .flatMap { value =>
        Try(flashCookieBaker.deserialize(flashCookieBaker.decode(value.value()))).toOption
      }
      .getOrElse(Flash())
  }
  lazy val attrs = TypedMap.apply(
    RequestAttrKey.Id      -> NettyRequest.counter.incrementAndGet(),
    RequestAttrKey.Session -> Cell(zeSession),
    RequestAttrKey.Flash -> Cell(zeFlash),
    RequestAttrKey.Server -> "netty-experimental",
    RequestAttrKey.Cookies -> Cell(Cookies(_cookies.toSeq.flatMap {
      case (_, cookies) => cookies.map {
        case cookie: io.netty.handler.codec.http.cookie.DefaultCookie => {
          play.api.mvc.Cookie(
            name = cookie.name(),
            value = cookie.value(),
            maxAge = Option(cookie.maxAge()).map(_.toInt),
            path = Option(cookie.path()).filter(_.nonEmpty).getOrElse("/"),
            domain = Option(cookie.domain()).filter(_.nonEmpty),
            secure = cookie.isSecure,
            httpOnly = cookie.isHttpOnly,
            sameSite = Option(cookie.sameSite()).map {
              case e if e == io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.None =>  play.api.mvc.Cookie.SameSite.None
              case e if e == io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Strict => play.api.mvc.Cookie.SameSite.Strict
              case e if e == io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Lax => play.api.mvc.Cookie.SameSite.Lax
              case _ => play.api.mvc.Cookie.SameSite.None
            }
          )
        }
        case cookie => {
          play.api.mvc.Cookie(
            name = cookie.name(),
            value = cookie.value(),
            maxAge = Option(cookie.maxAge()).map(_.toInt),
            path = Option(cookie.path()).filter(_.nonEmpty).getOrElse("/"),
            domain = Option(cookie.domain()).filter(_.nonEmpty),
            secure = cookie.isSecure,
            httpOnly = cookie.isHttpOnly,
            sameSite = None
          )
        }
      }
    }))
  )
  lazy val method: String = req.method().toString
  lazy val version: String = req.protocolVersion().toString
  lazy val headers: Headers = Headers(
    (req.headers().entries().asScala.map(e => (e.getKey, e.getValue)) ++ sessionOpt.map(s => ("Tls-Session-Info", s.toString))): _*
  )
  lazy val connection: RemoteConnection = new NettyRemoteConnection(req, ctx, secure, sessionOpt)
  lazy val target: RequestTarget = new NettyRequestTarget(req)
}

case class HttpServerBodyResponse(body: Publisher[Array[Byte]], contentType: Option[String], contentLength: Option[Long], chunked: Boolean)

case class HttpRequestParserConfig(
  allowDuplicateContentLengths: Boolean,
  validateHeaders: Boolean,
  h2cMaxContentLength: Int,
  initialBufferSize: Int,
  maxHeaderSize: Int,
  maxInitialLineLength: Int,
  maxChunkSize: Int,
)

case class Http3Settings(enabled: Boolean, port: Int)

case class ReactorNettyServerConfig(
  enabled: Boolean,
  newEngineOnly: Boolean,
  host: String,
  httpPort: Int,
  httpsPort: Int,
  nThread: Int,
  wiretap: Boolean,
  accessLog: Boolean,
  cipherSuites: Option[Seq[String]],
  protocols: Option[Seq[String]],
  clientAuth: ClientAuth,
  idleTimeout: java.time.Duration,
  parser: HttpRequestParserConfig,
  http3: Http3Settings,
)

object ReactorNettyServerConfig {
  def parseFrom(env: Env): ReactorNettyServerConfig = {
    val config = env.configuration.get[Configuration]("otoroshi.next.experimental.netty-server")
    ReactorNettyServerConfig(
      enabled = config.getOptionalWithFileSupport[Boolean]("enabled").getOrElse(false),
      newEngineOnly = config.getOptionalWithFileSupport[Boolean]("new-engine-only").getOrElse(false),
      host = config.getOptionalWithFileSupport[String]("host").getOrElse("0.0.0.0"),
      httpPort = config.getOptionalWithFileSupport[Int]("http-port").getOrElse(env.httpPort + 50),
      httpsPort = config.getOptionalWithFileSupport[Int]("https-port").getOrElse(env.httpsPort + 50),
      nThread = config.getOptionalWithFileSupport[Int]("threads").getOrElse(0),
      wiretap = config.getOptionalWithFileSupport[Boolean]("wiretap").getOrElse(false),
      accessLog = config.getOptionalWithFileSupport[Boolean]("accesslog").getOrElse(false),
      idleTimeout = config.getOptionalWithFileSupport[Long]("idleTimeout").map(l => java.time.Duration.ofMillis(l)).getOrElse(java.time.Duration.ofMillis(60000)),
      cipherSuites =
        env.configuration
          .getOptionalWithFileSupport[Seq[String]]("otoroshi.ssl.cipherSuites")
          .filterNot(_.isEmpty),
      protocols    =
        env.configuration
          .getOptionalWithFileSupport[Seq[String]]("otoroshi.ssl.protocols")
          .filterNot(_.isEmpty),
      clientAuth = {
        val auth = env.configuration
          .getOptionalWithFileSupport[String]("otoroshi.ssl.fromOutside.clientAuth")
          .flatMap(ClientAuth.apply)
          .getOrElse(ClientAuth.None)
        if (DynamicSSLEngineProvider.logger.isDebugEnabled)
          DynamicSSLEngineProvider.logger.debug(s"Otoroshi netty client auth: ${auth}")
        auth
      },
      parser = HttpRequestParserConfig(
        allowDuplicateContentLengths = config.getOptionalWithFileSupport[Boolean]("parser.allowDuplicateContentLengths").getOrElse(HttpDecoderSpec.DEFAULT_ALLOW_DUPLICATE_CONTENT_LENGTHS),
        validateHeaders = config.getOptionalWithFileSupport[Boolean]("parser.validateHeaders").getOrElse(HttpDecoderSpec.DEFAULT_VALIDATE_HEADERS),
        h2cMaxContentLength = config.getOptionalWithFileSupport[Int]("parser.h2cMaxContentLength").getOrElse(65536),
        initialBufferSize = config.getOptionalWithFileSupport[Int]("parser.initialBufferSize").getOrElse(HttpDecoderSpec.DEFAULT_INITIAL_BUFFER_SIZE),
        maxHeaderSize = config.getOptionalWithFileSupport[Int]("parser.maxHeaderSize").getOrElse(HttpDecoderSpec.DEFAULT_MAX_HEADER_SIZE),
        maxInitialLineLength = config.getOptionalWithFileSupport[Int]("parser.maxInitialLineLength").getOrElse(HttpDecoderSpec.DEFAULT_MAX_INITIAL_LINE_LENGTH),
        maxChunkSize = config.getOptionalWithFileSupport[Int]("parser.maxChunkSize").getOrElse(HttpDecoderSpec.DEFAULT_MAX_CHUNK_SIZE),
      ),
      http3 = Http3Settings(
        enabled = config.getOptionalWithFileSupport[Boolean]("http3.enabled").getOrElse(false),
        port = config.getOptionalWithFileSupport[Int]("http3.port").getOrElse(10050),
      )
    )
  }
}

class ReactorNettyServer(env: Env) {

  import reactor.core.publisher.Flux
  import reactor.netty.http.HttpProtocol
  import reactor.netty.http.server._

  implicit private val ec = env.otoroshiExecutionContext
  implicit private val mat = env.otoroshiMaterializer
  implicit private val ev = env

  private val logger = Logger("otoroshi-experimental-reactor-netty-server")

  private val engine: ProxyEngine = env.scriptManager.getAnyScript[RequestHandler](s"cp:${classOf[ProxyEngine].getName}").right.get.asInstanceOf[ProxyEngine]

  private val config = ReactorNettyServerConfig.parseFrom(env)

  private val cookieSignerProvider = new CookieSignerProvider(env.httpConfiguration.secret)
  private val sessionCookieBaker = new DefaultSessionCookieBaker(env.httpConfiguration.session, env.httpConfiguration.secret, cookieSignerProvider.get)
  private val flashCookieBaker =new DefaultFlashCookieBaker(env.httpConfiguration.flash, env.httpConfiguration.secret, cookieSignerProvider.get)
  private val cookieEncoder = new DefaultCookieHeaderEncoding(env.httpConfiguration.cookies)

  private def sendResultAsHttpResponse(result: Result, res: HttpServerResponse): NettyOutbound = {
    val bresponse: HttpServerBodyResponse = result.body match {
      case HttpEntity.NoEntity => HttpServerBodyResponse(Flux.empty[Array[Byte]](), None, None, false)
      case HttpEntity.Strict(data, contentType) => HttpServerBodyResponse(Flux.just(Seq(data.toArray[Byte]): _*), contentType, Some(data.size.toLong), false)
      case HttpEntity.Chunked(chunks, contentType) => {
        val publisher = chunks.collect {
          case HttpChunk.Chunk(data) => data.toArray[Byte]
        }.runWith(Sink.asPublisher(false))
        HttpServerBodyResponse(publisher, contentType, None, true)
      }
      case HttpEntity.Streamed(data, contentLength, contentType) => {
        val publisher = data.map(_.toArray[Byte]).runWith(Sink.asPublisher(false))
        HttpServerBodyResponse(publisher, contentType, contentLength, false)
      }
    }
    val headers = new DefaultHttpHeaders()
    result.header.headers.map {
      case (key, value) => headers.add(key, value)
    }
    bresponse.contentType.foreach(ct => headers.add("Content-Type", ct))
    bresponse.contentLength.foreach(cl => headers.addInt("Content-Length", cl.toInt))
    res
      .status(result.header.status)
      .headers(headers)
      .applyOnIf(result.newCookies.nonEmpty) { r =>
        result.newCookies.map { cookie =>
          val nettyCookie = new io.netty.handler.codec.http.cookie.DefaultCookie(cookie.name, cookie.value)
          nettyCookie.setPath(cookie.path)
          nettyCookie.setHttpOnly(cookie.httpOnly)
          nettyCookie.setSecure(cookie.secure)
          cookie.domain.foreach(d => nettyCookie.setDomain(d))
          cookie.maxAge.foreach(d => nettyCookie.setMaxAge(d.toLong))
          cookie.sameSite.foreach {
            case play.api.mvc.Cookie.SameSite.None => nettyCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.None)
            case play.api.mvc.Cookie.SameSite.Strict => nettyCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Strict)
            case play.api.mvc.Cookie.SameSite.Lax => nettyCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Lax)
          }
          r.addCookie(nettyCookie)
        }
        r
      }
      .applyOnIf(result.newSession.isDefined) { r =>
        result.newSession.map { session =>
          val cookie = sessionCookieBaker.encodeAsCookie(session)
          val sessionCookie = new io.netty.handler.codec.http.cookie.DefaultCookie(cookie.name, cookie.value)
          sessionCookie.setPath(cookie.path)
          sessionCookie.setHttpOnly(cookie.httpOnly)
          sessionCookie.setSecure(cookie.secure)
          cookie.domain.foreach(d => sessionCookie.setDomain(d))
          cookie.maxAge.foreach(d => sessionCookie.setMaxAge(d.toLong))
          cookie.sameSite.foreach {
            case play.api.mvc.Cookie.SameSite.None => sessionCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.None)
            case play.api.mvc.Cookie.SameSite.Strict => sessionCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Strict)
            case play.api.mvc.Cookie.SameSite.Lax => sessionCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Lax)
          }
          r.addCookie(sessionCookie)
        }
        r
      }
      .applyOnIf(result.newFlash.isDefined) { r =>
        result.newFlash.map { flash =>
          val cookie = flashCookieBaker.encodeAsCookie(flash)
          val flashCookie = new io.netty.handler.codec.http.cookie.DefaultCookie(cookie.name, cookie.value)
          flashCookie.setPath(cookie.path)
          flashCookie.setHttpOnly(cookie.httpOnly)
          flashCookie.setSecure(cookie.secure)
          cookie.domain.foreach(d => flashCookie.setDomain(d))
          cookie.maxAge.foreach(d => flashCookie.setMaxAge(d.toLong))
          cookie.sameSite.foreach {
            case play.api.mvc.Cookie.SameSite.None => flashCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.None)
            case play.api.mvc.Cookie.SameSite.Strict => flashCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Strict)
            case play.api.mvc.Cookie.SameSite.Lax => flashCookie.setSameSite(io.netty.handler.codec.http.cookie.CookieHeaderNames.SameSite.Lax)
          }
          r.addCookie(flashCookie)
        }
        r
      }
      .chunkedTransfer(bresponse.chunked)
      .keepAlive(true)
      .sendByteArray(bresponse.body)
  }

  private def frameToRawMessage(frame: WebSocketFrame): RawMessage = {
    Try {
      val builder = ByteString.newBuilder
      frame.content().readBytes(builder.asOutputStream, frame.content().readableBytes())
      val bytes = builder.result()
      val messageType = frame match {
        case _: TextWebSocketFrame         => MessageType.Text
        case _: BinaryWebSocketFrame       => MessageType.Binary
        case close: CloseWebSocketFrame    => MessageType.Close
        case _: PingWebSocketFrame         => MessageType.Ping
        case _: PongWebSocketFrame         => MessageType.Pong
        case _: ContinuationWebSocketFrame => MessageType.Continuation
      }
      RawMessage(messageType, bytes, frame.isFinalFragment)
    } match {
      case Failure(ex) =>
        ex.printStackTrace()
        RawMessage(MessageType.Text, ByteString("frameToRawMessage error: " + ex.getMessage), frame.isFinalFragment)
      case Success(s) => s
    }
  }

  private def messageToFrame(message: Message): WebSocketFrame = {
    import io.netty.handler.codec.http.websocketx._
    def byteStringToByteBuf(bytes: ByteString): ByteBuf = {
      if (bytes.isEmpty) {
        Unpooled.EMPTY_BUFFER
      } else {
        Unpooled.wrappedBuffer(bytes.asByteBuffer)
      }
    }
    message match {
      case play.api.http.websocket.TextMessage(data)                      => new TextWebSocketFrame(data)
      case play.api.http.websocket.BinaryMessage(data)                    => new BinaryWebSocketFrame(byteStringToByteBuf(data))
      case play.api.http.websocket.PingMessage(data)                      => new PingWebSocketFrame(byteStringToByteBuf(data))
      case play.api.http.websocket.PongMessage(data)                      => new PongWebSocketFrame(byteStringToByteBuf(data))
      case play.api.http.websocket.CloseMessage(Some(statusCode), reason) => new CloseWebSocketFrame(statusCode, reason)
      case play.api.http.websocket.CloseMessage(None, _)                  => new CloseWebSocketFrame()
    }
  }

  private def handleWebsocket(req: HttpServerRequest, res: HttpServerResponse, secure: Boolean, session: Option[SSLSession]): Publisher[Void] = {
    ReactiveStreamUtils.FluxUtils.fromFPublisher[Void] {
      val otoReq = new ReactorNettyRequestHeader(req, secure, session, sessionCookieBaker, flashCookieBaker)
      engine.handleWs(otoReq, engine.badDefaultRoutingWs).map {
        case Left(result) => sendResultAsHttpResponse(result, res)
        case Right(flow) => {
          res.sendWebsocket { (wsInbound, wsOutbound) =>
            val processor: Processor[RawMessage, Message] = WebSocketFlowHandler.webSocketProtocol(65536).join(flow).toProcessor.run()
            wsInbound
              .receiveFrames()
              .map[RawMessage](frameToRawMessage)
              .subscribe(processor)
            val fluxOut: Flux[WebSocketFrame] = Flux.from(processor).map(messageToFrame)
            wsOutbound.sendObject(fluxOut)
          }
        }
      }
    }
  }

  private def handleHttp(req: HttpServerRequest, res: HttpServerResponse, secure: Boolean, channel: Channel): Publisher[Void] = {
    val parent = channel.parent()
    val sslHandler = Option(parent.pipeline().get(classOf[SslHandler]))
    val sessionOpt = sslHandler.map(_.engine.getSession)
    val isWebSocket = (req.requestHeaders().contains("Upgrade") || req.requestHeaders().contains("upgrade")) &&
      (req.requestHeaders().contains("Sec-WebSocket-Version") || req.requestHeaders().contains("Sec-WebSocket-Version".toLowerCase)) &&
      Option(req.requestHeaders().get("Upgrade")).contains("websocket")
    if (isWebSocket) {
      handleWebsocket(req, res, secure, sessionOpt)
    } else {
      ReactiveStreamUtils.FluxUtils.fromFPublisher[Void] {
        val otoReq = new ReactorNettyRequest(req, secure, sessionOpt, sessionCookieBaker, flashCookieBaker)
        engine.handle(otoReq, engine.badDefaultRoutingHttp).map { result =>
          sendResultAsHttpResponse(result, res)
        }
      }
    }
  }

  private def handle(req: HttpServerRequest, res: HttpServerResponse, secure: Boolean, channel: Channel, handler: HttpRequestHandler): Publisher[Void] = {
    val parent = channel.parent()
    val sslHandler = Option(parent.pipeline().get(classOf[SslHandler]))
    val sessionOpt = sslHandler.map(_.engine.getSession)
    val isWebSocket = (req.requestHeaders().contains("Upgrade") || req.requestHeaders().contains("upgrade")) &&
      (req.requestHeaders().contains("Sec-WebSocket-Version") || req.requestHeaders().contains("Sec-WebSocket-Version".toLowerCase)) &&
      Option(req.requestHeaders().get("Upgrade")).contains("websocket")
    ReactiveStreamUtils.FluxUtils.fromFPublisher[Void] {
      val otoReq = new ReactorNettyRequest(req, secure, sessionOpt, sessionCookieBaker, flashCookieBaker)
      val (nreq, reqHandler) = handler.handlerForRequest(otoReq)
      reqHandler match {
        case a: EssentialAction => {
          a.apply(nreq).run(otoReq.body).map { result =>
            sendResultAsHttpResponse(result, res)
          }
        }
        case a: WebSocket if isWebSocket => {
          a.apply(nreq).map {
            case Left(result) => sendResultAsHttpResponse(result, res)
            case Right(flow) => {
              res.sendWebsocket { (wsInbound, wsOutbound) =>
                val processor: Processor[RawMessage, Message] = WebSocketFlowHandler.webSocketProtocol(65536).join(flow).toProcessor.run()
                wsInbound
                  .receiveFrames()
                  .map[RawMessage](frameToRawMessage)
                  .subscribe(processor)
                val fluxOut: Flux[WebSocketFrame] = Flux.from(processor).map(messageToFrame)
                wsOutbound.sendObject(fluxOut)
              }
            }
          }
        }
        case a => {
          sendResultAsHttpResponse(Results.InternalServerError(Json.obj("err" -> s"unknown handler: ${a.getClass.getName} - ${a}")), res).vfuture
        }
      }
    }
  }

  private def setupSslContext(): SSLContext = {
    new SSLContext(
      new SSLContextSpi() {
        override def engineCreateSSLEngine(): SSLEngine                     = DynamicSSLEngineProvider.createSSLEngine(config.clientAuth, config.cipherSuites, config.protocols, None)
        override def engineCreateSSLEngine(s: String, i: Int): SSLEngine    = engineCreateSSLEngine()
        override def engineInit(
                                 keyManagers: Array[KeyManager],
                                 trustManagers: Array[TrustManager],
                                 secureRandom: SecureRandom
                               ): Unit                                                             = ()
        override def engineGetClientSessionContext(): SSLSessionContext     =
          DynamicSSLEngineProvider.currentServer.getClientSessionContext
        override def engineGetServerSessionContext(): SSLSessionContext     =
          DynamicSSLEngineProvider.currentServer.getServerSessionContext
        override def engineGetSocketFactory(): SSLSocketFactory             =
          DynamicSSLEngineProvider.currentServer.getSocketFactory
        override def engineGetServerSocketFactory(): SSLServerSocketFactory =
          DynamicSSLEngineProvider.currentServer.getServerSocketFactory
      },
      new Provider(
        "[NETTY] Otoroshi SSlEngineProvider delegate",
        "1.0",
        "[NETTY] A provider that delegates calls to otoroshi dynamic one"
      )                   {},
      "[NETTY] Otoroshi SSLEngineProvider delegate"
    ) {}
  }

  def startHttp3(handler: HttpRequestHandler): Unit = {

    /*
    val ssc = new SelfSignedCertificate()
      val serverCtx =
        QuicSslContextBuilder.forServer(ssc.privateKey(), null, ssc.certificate())
          .applicationProtocols("http/1.1")
          .build()
      val quicServer = QuicServer.create()
        .host(config.host)
        .port(10050)
        .applyOnIf(config.wiretap)(_.wiretap(logger.logger.getName + "-wiretap-quic", LogLevel.INFO))
        .secure(serverCtx)
        .tokenHandler(InsecureQuicTokenHandler.INSTANCE)
        .idleTimeout(java.time.Duration.ofSeconds(5))
        .initialSettings { spec =>
          spec.maxData(10000000)
            .maxStreamDataBidirectionalRemote(1000000)
            .maxStreamsBidirectional(100)
        }
        .handleStream((in, out) => out.send(in.receive().retain()))
        .bindNow()
     */

    if (config.http3.enabled) {

      import io.netty.bootstrap._
      import io.netty.channel._
      import io.netty.channel.socket.nio._
      import io.netty.incubator.codec.http3.{Http3, Http3FrameToHttpObjectCodec, Http3ServerConnectionHandler}
      import io.netty.incubator.codec.quic.{InsecureQuicTokenHandler, QuicChannel, QuicStreamChannel}

      import java.util.concurrent.TimeUnit

      class Http1RequestHandler extends ChannelInboundHandlerAdapter {

        private val NOT_HANDLED = Unpooled.wrappedBuffer(s"${Json.obj("error" -> "not handled")}\r\n".getBytes(CharsetUtil.US_ASCII))
        private val NOT_ESSENTIAL_ACTION = Unpooled.wrappedBuffer(s"${Json.obj("error" -> "not essential action")}\r\n".getBytes(CharsetUtil.US_ASCII))
        private val ERROR = Unpooled.wrappedBuffer(s"${Json.obj("error" -> "error")}\r\n".getBytes(CharsetUtil.US_ASCII))

        private var body: ByteString = ByteString.empty

        def send100Continue(ctx: ChannelHandlerContext): Unit = {
          val response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE, Unpooled.EMPTY_BUFFER)
          ctx.write(response)
        }

        override def exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
          cause.printStackTrace()
          ctx.close()
        }

        override def channelRead(ctx: ChannelHandlerContext, msg: Any): Unit = {
          // TODO: SSLSession ???
          msg match {
            case req: FullHttpRequest => {
              if (HttpUtil.is100ContinueExpected(req)) {
                send100Continue(ctx)
                ReferenceCountUtil.release(msg)
              } else {
                val keepAlive = HttpUtil.isKeepAlive(req)
                def go(): Unit = {
                  val otoReq = new NettyRequest(req, ctx, body, true, None, sessionCookieBaker, flashCookieBaker)
                  val (nreq, reqHandler) = handler.handlerForRequest(otoReq)
                  reqHandler match {
                    case a: EssentialAction => {
                      a.apply(nreq).run(otoReq.body).flatMap { result =>
                        result.body.dataStream.runFold(ByteString.empty)(_ ++ _).map { body =>
                          val response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(result.header.status), Unpooled.copiedBuffer(body.toArray))
                          result.header.headers.foreach {
                            case (key, value) => response.headers().set(key, value)
                          }
                          // TODO: keepalive: https://github.com/netty/netty/blob/4.1/example/src/main/java/io/netty/example/http/snoop/HttpSnoopServerHandler.java#L157
                          //                  https://github.com/netty/netty/blob/4.1/example/src/main/java/io/netty/example/http/snoop/HttpSnoopServerHandler.java#L128
                          // TODO: cookie: https://github.com/netty/netty/blob/4.1/example/src/main/java/io/netty/example/http/snoop/HttpSnoopServerHandler.java#L177
                          result.body.contentLength.foreach(l => response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, l.toInt))
                          result.body.contentType.foreach(l => response.headers().set(HttpHeaderNames.CONTENT_TYPE, l))
                          if (keepAlive) {
                            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE)
                            ctx.write(response)
                            ctx.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE) // TODO: why ???
                          } else {
                            ctx.write(response)
                            ctx.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE)
                          }
                          ReferenceCountUtil.release(msg)
                        }
                      }.andThen {
                        case Failure(exception) => {
                          exception.printStackTrace()
                          val response = new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1, HttpResponseStatus.OK, ERROR.retainedDuplicate())
                          response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, ERROR.readableBytes())
                          ctx.writeAndFlush(response)
                          ReferenceCountUtil.release(msg)
                        }
                      }
                    }
                    case _ => {
                      val response = new DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, HttpResponseStatus.OK, NOT_ESSENTIAL_ACTION.retainedDuplicate())
                      response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, NOT_ESSENTIAL_ACTION.readableBytes())
                      ctx.writeAndFlush(response)
                      ReferenceCountUtil.release(msg)
                    }
                  }
                }

                if (msg.isInstanceOf[HttpRequest]) {
                  // TODO: trigger route without body yet
                }
                if (msg.isInstanceOf[HttpContent]) {
                  val contentMsg = msg.asInstanceOf[HttpContent]
                  val content = contentMsg.content()
                  if (content.isReadable()) {
                    body = body ++ ByteString(content.array())
                  }
                  if (msg.isInstanceOf[LastHttpContent]) {
                    // TODO: handle trailer headers
                    // TODO: stream body ;)
                    go()
                  }
                } else if (msg.isInstanceOf[LastHttpContent]) {
                  // TODO: handle trailer headers
                  // TODO: stream body ;)
                  go()
                }
              }
            }
            case _ => {
              val response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK, NOT_HANDLED.retainedDuplicate())
              response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, NOT_HANDLED.readableBytes())
              ctx.writeAndFlush(response)
              ReferenceCountUtil.release(msg)
            }
          }
        }
      }

      val cert = new SelfSignedCertificate()
      val sslContext = QuicSslContextBuilder.forServer(cert.key(), null, cert.cert())
        .applicationProtocols(Http3.supportedApplicationProtocols():_*).earlyData(true).build()

      val codec = Http3.newQuicServerCodecBuilder
        //.option(QuicChannelOption.UDP_SEGMENTS, 10)
        .sslContext(sslContext)
        .maxIdleTimeout(config.idleTimeout.toMillis, TimeUnit.MILLISECONDS)
        .maxSendUdpPayloadSize(1500)
        .maxRecvUdpPayloadSize(1500)
        .initialMaxData(10000000)
        .initialMaxStreamDataBidirectionalLocal(1000000)
        .initialMaxStreamDataBidirectionalRemote(1000000)
        .initialMaxStreamsBidirectional(100000)
        .tokenHandler(InsecureQuicTokenHandler.INSTANCE)
        .handler(new ChannelInitializer[QuicChannel]() {
          override def initChannel(ch: QuicChannel): Unit = {
            ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
              @Override
              override def channelInactive(ctx: ChannelHandlerContext): Unit = {
                // System.err.println("INACTIVE")
                // ctx.channel().asInstanceOf[QuicChannel].collectStats().addListener(f => {
                //   // System.err.println(f.getNow())
                //   println("yep")
                // })
              }
            })
            ch.pipeline().addLast(new Http3ServerConnectionHandler(
              new ChannelInitializer[QuicStreamChannel]() {
                // Called for each request-stream,
                override def initChannel(ch: QuicStreamChannel): Unit = {
                  ch.pipeline().addLast(new Http3FrameToHttpObjectCodec(true))
                  ch.pipeline().addLast(new Http1RequestHandler())
                }
              }))
          }
        }).build()
      val group = new NioEventLoopGroup(1)
      val bs = new Bootstrap()
      val channel = bs.group(group)
        .channel(classOf[NioDatagramChannel])
        .handler(codec)
        .bind(config.host, config.http3.port)
        .sync()
        .channel()
      channel.closeFuture()
      Runtime.getRuntime.addShutdownHook(new Thread(() => {
        group.shutdownGracefully();
      }))
    }
  }

  def start(handler: HttpRequestHandler): Unit = {
    if (config.enabled) {

      logger.info("")
      logger.info(s"Starting the experimental Reactor Netty Server !!!")
      logger.info("")
      val (groupHttp: EventLoopGroup, groupHttps: EventLoopGroup) = if (io.netty.channel.epoll.Epoll.isAvailable) {
        logger.info("  using Epoll native transport")
        logger.info("")
        val channelHttp = new io.netty.channel.epoll.EpollServerSocketChannel()
        val channelHttps = new io.netty.channel.epoll.EpollServerSocketChannel()
        val evlGroupHttp = new io.netty.channel.epoll.EpollEventLoopGroup(config.nThread)
        val evlGroupHttps = new io.netty.channel.epoll.EpollEventLoopGroup(config.nThread)
        evlGroupHttp.register(channelHttp)
        evlGroupHttps.register(channelHttps)
        (evlGroupHttp, evlGroupHttps)
      } else if (io.netty.channel.kqueue.KQueue.isAvailable) {
        logger.info("  using KQueue native transport")
        logger.info("")
        val channelHttp = new io.netty.channel.kqueue.KQueueServerSocketChannel()
        val channelHttps = new io.netty.channel.kqueue.KQueueServerSocketChannel()
        val evlGroupHttp = new io.netty.channel.kqueue.KQueueEventLoopGroup(config.nThread)
        val evlGroupHttps = new io.netty.channel.kqueue.KQueueEventLoopGroup(config.nThread)
        evlGroupHttp.register(channelHttp)
        evlGroupHttps.register(channelHttps)
        (evlGroupHttp, evlGroupHttps)
      } else if (io.netty.incubator.channel.uring.IOUring.isAvailable) {
        logger.info("  using IO-Uring native transport")
        logger.info("")
        val channelHttp = new io.netty.incubator.channel.uring.IOUringServerSocketChannel()
        val channelHttps = new io.netty.incubator.channel.uring.IOUringServerSocketChannel()
        val evlGroupHttp = new io.netty.incubator.channel.uring.IOUringEventLoopGroup(config.nThread)
        val evlGroupHttps = new io.netty.incubator.channel.uring.IOUringEventLoopGroup(config.nThread)
        evlGroupHttp.register(channelHttp)
        evlGroupHttps.register(channelHttps)
        (evlGroupHttp, evlGroupHttps)
      } else {
        val channelHttp = new NioServerSocketChannel()
        val channelHttps = new NioServerSocketChannel()
        val evlGroupHttp = new NioEventLoopGroup(config.nThread)
        val evlGroupHttps = new NioEventLoopGroup(config.nThread)
        evlGroupHttp.register(channelHttp)
        evlGroupHttps.register(channelHttps)
        (evlGroupHttp, evlGroupHttps)
      }
      logger.info(s"  https://${config.host}:${config.httpsPort}")
      logger.info(s"  http://${config.host}:${config.httpPort}")
      if (config.http3.enabled) logger.info(s"  https://${config.host}:${config.http3.port} (HTTP/3)")
      logger.info("")

      def handleFunction(secure: Boolean): BiFunction[_ >: HttpServerRequest, _ >: HttpServerResponse, _ <: Publisher[Void]] = {
        if (config.newEngineOnly) {
          (req, res) => {
            val channel = NettyHelper.getChannel(req)
            handleHttp(req, res, secure, channel)
          }
        } else {
          (req, res) => {
            val channel = NettyHelper.getChannel(req)
            handle(req, res, secure, channel, handler)
          }
        }
      }

      val serverHttps = HttpServer
        .create()
        .host(config.host)
        .accessLog(config.accessLog)
        .applyOnIf(config.wiretap)(_.wiretap(logger.logger.getName + "-wiretap-https", LogLevel.INFO))
        .port(config.httpsPort)
        .protocol(HttpProtocol.HTTP11, HttpProtocol.H2C)
        .runOn(groupHttps)
        .httpRequestDecoder(spec => spec
          .allowDuplicateContentLengths(config.parser.allowDuplicateContentLengths)
          .h2cMaxContentLength(config.parser.h2cMaxContentLength)
          .initialBufferSize(config.parser.initialBufferSize)
          .maxHeaderSize(config.parser.maxHeaderSize)
          .maxInitialLineLength(config.parser.maxInitialLineLength)
          .maxChunkSize(config.parser.maxChunkSize)
          .validateHeaders(config.parser.validateHeaders)
        )
        .idleTimeout(config.idleTimeout)
        .doOnChannelInit { (observer, channel, socket) =>
          val engine = setupSslContext().createSSLEngine()
          engine.setHandshakeApplicationProtocolSelector((e, protocols) => {
            protocols match {
              case ps if ps.contains("h2") => "h2"
              case ps if ps.contains("spdy/3") => "spdy/3"
              case _ => "http/1.1"
            }
          })
          // we do not use .secure() because of no dynamic sni support and use SslHandler instead !
          channel.pipeline().addFirst(new SslHandler(engine))
        }
        .handle(handleFunction(true))
        .bindNow()
      val serverHttp = HttpServer
        .create()
        .host(config.host)
        .noSSL()
        .accessLog(config.accessLog)
        .applyOnIf(config.wiretap)(_.wiretap(logger.logger.getName + "-wiretap-http", LogLevel.INFO))
        .port(config.httpPort)
        .protocol(HttpProtocol.H2C, HttpProtocol.HTTP11)
        .handle(handleFunction(false))
        .runOn(groupHttp)
        .httpRequestDecoder(spec => spec
          .allowDuplicateContentLengths(config.parser.allowDuplicateContentLengths)
          .h2cMaxContentLength(config.parser.h2cMaxContentLength)
          .initialBufferSize(config.parser.initialBufferSize)
          .maxHeaderSize(config.parser.maxHeaderSize)
          .maxInitialLineLength(config.parser.maxInitialLineLength)
          .maxChunkSize(config.parser.maxChunkSize)
          .validateHeaders(config.parser.validateHeaders)
        )
        .idleTimeout(config.idleTimeout)
        .bindNow()
      startHttp3(handler)
      Runtime.getRuntime.addShutdownHook(new Thread(() => {
        serverHttp.disposeNow()
        serverHttps.disposeNow()
      }))
    } else {
      ()
    }
  }
}