package otoroshi.gateway

import java.net.{InetAddress, InetSocketAddress}
import java.util.concurrent.atomic.AtomicReference
import akka.{Done, NotUsed}
import akka.actor.{Actor, ActorRef, PoisonPill, Props}
import akka.http.scaladsl.ClientTransport
import akka.http.scaladsl.model.Uri
import akka.http.scaladsl.model.headers.RawHeader
import akka.http.scaladsl.model.ws.{BinaryMessage, InvalidUpgradeResponse, TextMessage, ValidUpgrade, WebSocketRequest}
import akka.http.scaladsl.settings.ClientConnectionSettings
import akka.http.scaladsl.util.FastFuture
import akka.stream.scaladsl.{Flow, Keep, Sink, Source, SourceQueueWithComplete, Tcp}
import akka.stream.{FlowShape, Materializer, OverflowStrategy}
import akka.util.ByteString
import otoroshi.env.Env
import otoroshi.events._
import otoroshi.models._
import org.joda.time.DateTime
import otoroshi.el.TargetExpressionLanguage
import otoroshi.next.models.{NgPluginInstance, NgRoute}
import otoroshi.next.plugins.api.{NgAccess, NgPluginWrapper, NgTransformerRequestContext, NgWebsocketPlugin, NgWebsocketPluginContext}
import otoroshi.next.proxy.NgProxyEngineError
import otoroshi.next.proxy.NgProxyEngineError.NgResultProxyEngineError
import otoroshi.next.utils.FEither
import otoroshi.script.Implicits._
import otoroshi.script.TransformerRequestContext
import otoroshi.utils.UrlSanitizer
import play.api.Logger
import play.api.http.websocket.{CloseMessage, PingMessage, PongMessage, BinaryMessage => PlayWSBinaryMessage, Message => PlayWSMessage, TextMessage => PlayWSTextMessage}
import play.api.libs.json.{JsValue, Json}
import play.api.libs.streams.ActorFlow
import play.api.libs.ws.DefaultWSCookie
import play.api.mvc.Results.NotFound
import play.api.mvc._
import otoroshi.security.{IdGenerator, OtoroshiClaim}
import otoroshi.utils.http.RequestImplicits._
import otoroshi.utils.http.{HeadersHelper, ManualResolveTransport, WSCookieWithSameSite, WSProxyServerUtils}
import otoroshi.utils.udp._
import otoroshi.utils.future.Implicits._

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.util.{Failure, Success, Try}

class WebSocketHandler()(implicit env: Env) {

  type WSFlow = Flow[PlayWSMessage, PlayWSMessage, _]

  implicit lazy val currentEc           = env.otoroshiExecutionContext
  implicit lazy val currentScheduler    = env.otoroshiScheduler
  implicit lazy val currentSystem       = env.otoroshiActorSystem
  implicit lazy val currentMaterializer = env.otoroshiMaterializer

  lazy val logger = Logger("otoroshi-websocket-handler")

  def forwardCall(
      reverseProxyAction: ReverseProxyAction,
      snowMonkey: SnowMonkey,
      headersInFiltered: Seq[String],
      headersOutFiltered: Seq[String]
  ) = {
    WebSocket.acceptOrResult[PlayWSMessage, PlayWSMessage] { req =>
      reverseProxyAction.async[WSFlow](
        ReverseProxyActionContext(req, Source.empty, snowMonkey, logger),
        true,
        c => actuallyCallDownstream(c, headersInFiltered, headersOutFiltered)
      )
    }
  }

  def forwardCallRaw(
      req: RequestHeader,
      reverseProxyAction: ReverseProxyAction,
      snowMonkey: SnowMonkey,
      headersInFiltered: Seq[String],
      headersOutFiltered: Seq[String]
  ) = {
    reverseProxyAction.async[WSFlow](
      ReverseProxyActionContext(req, Source.empty, snowMonkey, logger),
      true,
      c => actuallyCallDownstream(c, headersInFiltered, headersOutFiltered)
    )
  }

  def actuallyCallDownstream(
      ctx: ActualCallContext,
      headersInFiltered: Seq[String],
      headersOutFiltered: Seq[String]
  ): Future[Either[Result, Flow[PlayWSMessage, PlayWSMessage, _]]] = {

    val ActualCallContext(
      req,
      descriptor,
      _target,
      apiKey,
      paUsr,
      jwtInjection,
      snowMonkeyContext,
      snowflake,
      attrs,
      elCtx,
      globalConfig,
      withTrackingCookies,
      bodyAlreadyConsumed,
      requestBody,
      secondStart,
      firstOverhead,
      cbDuration,
      callAttempts,
      attempts,
      alreadyFailed
    ) = ctx

    val counterIn        = attrs.get(otoroshi.plugins.Keys.RequestCounterInKey).get
    val counterOut       = attrs.get(otoroshi.plugins.Keys.RequestCounterOutKey).get
    val canaryId         = attrs.get(otoroshi.plugins.Keys.RequestCanaryIdKey).get
    val callDate         = attrs.get(otoroshi.plugins.Keys.RequestTimestampKey).get
    val start            = attrs.get(otoroshi.plugins.Keys.RequestStartKey).get
    val requestTimestamp = callDate.toString("yyyy-MM-dd'T'HH:mm:ss.SSSZZ")

    if (logger.isTraceEnabled) logger.trace("[WEBSOCKET] Call backend !!!")
    val stateValue         = IdGenerator.extendedToken(128)
    val stateToken: String = descriptor.secComVersion match {
      case SecComVersion.V1 => stateValue
      case SecComVersion.V2 =>
        OtoroshiClaim(
          iss = env.Headers.OtoroshiIssuer,
          sub = env.Headers.OtoroshiIssuer,
          aud = descriptor.name,
          exp = DateTime
            .now()
            .plus(descriptor.secComTtl.toMillis)
            .toDate
            .getTime,
          iat = DateTime.now().toDate.getTime,
          jti = IdGenerator.uuid
        ).withClaim("state", stateValue)
          .serialize(descriptor.algoChallengeFromOtoToBack)
    }
    val rawUri             = req.relativeUri.substring(1)
    val uriParts           = rawUri.split("/").toSeq
    val uri: String        = descriptor.maybeStrippedUri(req, rawUri)
    // val index = reqCounter.incrementAndGet() % (if (descriptor.targets.nonEmpty) descriptor.targets.size else 1)
    // // Round robin loadbalancing is happening here !!!!!
    // val target = descriptor.targets.apply(index.toInt)
    val scheme             =
      if (descriptor.redirectToLocal) descriptor.localScheme else _target.scheme
    val host               = if (descriptor.redirectToLocal) descriptor.localHost else _target.host
    val root               = descriptor.root
    val url                = TargetExpressionLanguage(
      s"${if (_target.scheme == "https") "wss" else "ws"}://$host$root$uri",
      Some(req),
      Some(descriptor),
      None,
      apiKey,
      paUsr,
      elCtx,
      attrs,
      env
    )
    // val queryString = req.queryString.toSeq.flatMap { case (key, values) => values.map(v => (key, v)) }
    val fromOtoroshi       = req.headers
      .get(env.Headers.OtoroshiRequestId)
      .orElse(req.headers.get(env.Headers.OtoroshiGatewayParentRequest))
    val promise            = Promise[ProxyDone]

    val claim = descriptor.generateInfoToken(apiKey, paUsr, Some(req))
    if (logger.isTraceEnabled) logger.trace(s"Claim is : $claim")
    attrs.put(otoroshi.plugins.Keys.OtoTokenKey -> claim.payload)

    //val stateRequestHeaderName =
    //  descriptor.secComHeaders.stateRequestName.getOrElse(env.Headers.OtoroshiState)
    val stateResponseHeaderName =
      descriptor.secComHeaders.stateResponseName
        .getOrElse(env.Headers.OtoroshiStateResp)

    val headersIn: Seq[(String, String)] = HeadersHelper.composeHeadersIn(
      descriptor = descriptor,
      req = req,
      apiKey = apiKey,
      paUsr = paUsr,
      elCtx = elCtx,
      currentReqHasBody = false,
      headersInFiltered = headersInFiltered,
      snowflake = snowflake,
      requestTimestamp = requestTimestamp,
      host = host,
      claim = claim,
      stateToken = stateToken,
      fromOtoroshi = fromOtoroshi,
      snowMonkeyContext = SnowMonkeyContext(
        Source.empty[ByteString],
        Source.empty[ByteString]
      ),
      jwtInjection = jwtInjection,
      attrs = attrs
    )
    if (logger.isTraceEnabled)
      logger.trace(
        s"[WEBSOCKET] calling '$url' with headers \n ${headersIn.map(_.toString()) mkString "\n"}"
      )
    val overhead                         = System.currentTimeMillis() - start
    val quotas: Future[RemainingQuotas]  =
      apiKey.map(_.updateQuotas()).getOrElse(FastFuture.successful(RemainingQuotas()))
    promise.future.andThen {
      case Success(resp) => {
        val duration = System.currentTimeMillis() - start
        // logger.trace(s"[$snowflake] Call forwarded in $duration ms. with $overhead ms overhead for (${req.version}, ${req.theProtocol}://${req.host}${req.relativeUri} => $url, $from)")
        descriptor
          .updateMetrics(duration, overhead, counterIn.get(), counterOut.get(), 0, globalConfig)
          .andThen { case Failure(e) =>
            logger.error("Error while updating call metrics reporting", e)
          }
        env.datastores.globalConfigDataStore.updateQuotas(globalConfig)
        quotas.andThen {
          case Success(q) => {
            val fromLbl          =
              req.headers.get(env.Headers.OtoroshiVizFromLabel).getOrElse("internet")
            val viz: OtoroshiViz = OtoroshiViz(
              to = descriptor.id,
              toLbl = descriptor.name,
              from = req.headers.get(env.Headers.OtoroshiVizFrom).getOrElse("internet"),
              fromLbl = fromLbl,
              fromTo = s"$fromLbl###${descriptor.name}"
            )
            val evt              = GatewayEvent(
              `@id` = env.snowflakeGenerator.nextIdStr(),
              reqId = snowflake,
              parentReqId = fromOtoroshi,
              `@timestamp` = DateTime.now(),
              `@calledAt` = callDate,
              protocol = req.version,
              to = Location(
                scheme = req.theWsProtocol,
                host = req.theHost,
                uri = req.relativeUri
              ),
              target = Location(
                scheme = scheme,
                host = host,
                uri = req.relativeUri
              ),
              backendDuration = attrs.get(otoroshi.plugins.Keys.BackendDurationKey).getOrElse(-1L),
              duration = duration,
              overhead = overhead,
              cbDuration = cbDuration,
              overheadWoCb = Math.abs(overhead - cbDuration),
              callAttempts = callAttempts,
              url = url,
              method = req.method,
              from = req.theIpAddress,
              env = descriptor.env,
              data = DataInOut(
                dataIn = counterIn.get(),
                dataOut = counterOut.get()
              ),
              status = resp.status,
              headers = req.headers.toSimpleMap.toSeq.map(Header.apply),
              headersOut = resp.headersOut,
              otoroshiHeadersIn = resp.otoroshiHeadersIn,
              otoroshiHeadersOut = resp.otoroshiHeadersOut,
              extraInfos = attrs.get(otoroshi.plugins.Keys.GatewayEventExtraInfosKey),
              identity = apiKey
                .map(k =>
                  Identity(
                    identityType = "APIKEY",
                    identity = k.clientId,
                    label = k.clientName
                  )
                )
                .orElse(
                  paUsr.map(k =>
                    Identity(
                      identityType = "PRIVATEAPP",
                      identity = k.email,
                      label = k.name
                    )
                  )
                ),
              responseChunked = false,
              `@serviceId` = descriptor.id,
              `@service` = descriptor.name,
              descriptor = Some(descriptor),
              `@product` = descriptor.metadata.getOrElse("product", "--"),
              remainingQuotas = q,
              viz = Some(viz),
              clientCertChain = req.clientCertChainPem,
              err = attrs.get(otoroshi.plugins.Keys.GwErrorKey).isDefined,
              gwError = attrs.get(otoroshi.plugins.Keys.GwErrorKey).map(_.message),
              userAgentInfo = attrs.get[JsValue](otoroshi.plugins.Keys.UserAgentInfoKey),
              geolocationInfo = attrs.get[JsValue](otoroshi.plugins.Keys.GeolocationInfoKey),
              extraAnalyticsData = attrs.get[JsValue](otoroshi.plugins.Keys.ExtraAnalyticsDataKey)
            )
            evt.toAnalytics()
            if (descriptor.logAnalyticsOnServer) {
              evt.log()(env, env.analyticsExecutionContext) // pressure EC
            }
          }
        }(env.analyticsExecutionContext) // pressure EC
      }
    }(env.analyticsExecutionContext) // pressure EC

    val wsCookiesIn     = req.cookies.toSeq.map(c =>
      WSCookieWithSameSite(
        name = c.name,
        value = c.value,
        domain = c.domain,
        path = Option(c.path),
        maxAge = c.maxAge.map(_.toLong),
        secure = c.secure,
        httpOnly = c.httpOnly,
        sameSite = c.sameSite
      )
    )
    val rawRequest      = otoroshi.script.HttpRequest(
      url = s"${req.theProtocol}://${req.theHost}${req.relativeUri}",
      method = req.method,
      headers = req.headers.toSimpleMap,
      cookies = wsCookiesIn,
      version = req.version,
      clientCertificateChain = req.clientCertificateChain,
      target = None,
      claims = claim,
      body = () => requestBody
    )
    val otoroshiRequest = otoroshi.script.HttpRequest(
      url = url,
      method = req.method,
      headers = headersIn.toMap,
      cookies = wsCookiesIn,
      version = req.version,
      clientCertificateChain = req.clientCertificateChain,
      target = Some(_target),
      claims = claim,
      body = () => requestBody
    )
    val upstreamStart   = System.currentTimeMillis()
    descriptor
      .transformRequest(
        TransformerRequestContext(
          index = -1,
          snowflake = snowflake,
          rawRequest = rawRequest,
          otoroshiRequest = otoroshiRequest,
          descriptor = descriptor,
          apikey = apiKey,
          user = paUsr,
          request = req,
          config = descriptor.transformerConfig,
          attrs = attrs
        )
      )
      .flatMap {
        case Left(badResult)                                   => {
          quotas
            .map { remainingQuotas =>
              val _headersOut: Seq[(String, String)] =
                HeadersHelper.composeHeadersOutBadResult(
                  descriptor = descriptor,
                  req = req,
                  badResult = badResult,
                  apiKey = apiKey,
                  paUsr = paUsr,
                  elCtx = elCtx,
                  snowflake = snowflake,
                  requestTimestamp = requestTimestamp,
                  headersOutFiltered = headersOutFiltered,
                  overhead = overhead,
                  upstreamLatency = 0L,
                  canaryId = canaryId,
                  remainingQuotas = remainingQuotas,
                  attrs = attrs
                )

              promise.trySuccess(
                ProxyDone(
                  badResult.header.status,
                  false,
                  0,
                  headersOut = badResult.header.headers.toSeq.map(Header.apply),
                  otoroshiHeadersOut = _headersOut.map(Header.apply),
                  otoroshiHeadersIn = headersIn.map(Header.apply)
                )
              )
              badResult.withHeaders(_headersOut: _*)
            }
            .asLeft[WSFlow]
        }
        case Right(_)
            if descriptor.tcpUdpTunneling && !req.relativeUri
              .startsWith("/.well-known/otoroshi/tunnel") => {
          Errors
            .craftResponseResult(
              s"Resource not found",
              NotFound,
              req,
              None,
              Some("errors.resource.not.found"),
              attrs = attrs
            )
            .asLeft[WSFlow]
        }
        case Right(_httpReq)
            if descriptor.tcpUdpTunneling && req.relativeUri
              .startsWith("/.well-known/otoroshi/tunnel") => {
          val target                          = _httpReq.target.getOrElse(_target)
          val (theHost: String, thePort: Int) =
            (
              target.scheme,
              TargetExpressionLanguage(target.host, Some(req), Some(descriptor), None, apiKey, paUsr, elCtx, attrs, env)
            ) match {
              case (_, host) if host.contains(":")            =>
                (host.split(":").apply(0), host.split(":").apply(1).toInt)
              case (scheme, host) if scheme.contains("https") => (host, 443)
              case (_, host)                                  => (host, 80)
            }
          val remoteAddress                   = target.ipAddress match {
            case Some(ip) =>
              new InetSocketAddress(
                InetAddress.getByAddress(theHost, InetAddress.getByName(ip).getAddress),
                thePort
              )
            case None     => new InetSocketAddress(theHost, thePort)
          }
          req
            .getQueryString("transport")
            .map(_.toLowerCase())
            .getOrElse("tcp") match {
            case "tcp"     => {
              val flow: Flow[PlayWSMessage, PlayWSMessage, _] =
                Flow[PlayWSMessage]
                  .collect {
                    case PlayWSBinaryMessage(data) =>
                      data
                    case _                         =>
                      ByteString.empty
                  }
                  .via(
                    Tcp()
                      .outgoingConnection(
                        remoteAddress = remoteAddress,
                        connectTimeout = descriptor.clientConfig.connectionTimeout.millis,
                        idleTimeout = descriptor.clientConfig.idleTimeout.millis
                      )
                      .map(bs => PlayWSBinaryMessage(bs))
                  )
                  .alsoTo(Sink.onComplete { case _ =>
                    promise.trySuccess(
                      ProxyDone(
                        200,
                        false,
                        0,
                        Seq.empty[Header],
                        Seq.empty[Header],
                        Seq.empty[Header]
                      )
                    )
                  })
              FastFuture.successful(Right(flow))
            }
            case "udp-old" => {
              val flow: Flow[PlayWSMessage, PlayWSMessage, _] =
                Flow[PlayWSMessage]
                  .collect {
                    case PlayWSBinaryMessage(data) =>
                      Datagram(data, remoteAddress)
                    case _                         =>
                      Datagram(ByteString.empty, remoteAddress)
                  }
                  .via(
                    UdpClient
                      .flow(new InetSocketAddress("0.0.0.0", 0))
                      .map(dg => PlayWSBinaryMessage(dg.data))
                  )
                  .alsoTo(Sink.onComplete { case _ =>
                    promise.trySuccess(
                      ProxyDone(
                        200,
                        false,
                        0,
                        Seq.empty[Header],
                        Seq.empty[Header],
                        Seq.empty[Header]
                      )
                    )
                  })
              FastFuture.successful(Right(flow))
            }
            case "udp"     => {

              import akka.stream.scaladsl.{Flow, GraphDSL, UnzipWith, ZipWith}
              import GraphDSL.Implicits._

              val base64decoder = java.util.Base64.getDecoder
              val base64encoder = java.util.Base64.getEncoder

              val fromJson: Flow[PlayWSMessage, (Int, String, Datagram), NotUsed] =
                Flow[PlayWSMessage].collect {
                  case PlayWSBinaryMessage(data) =>
                    val json              = Json.parse(data.utf8String)
                    val port: Int         = (json \ "port").as[Int]
                    val address: String   = (json \ "address").as[String]
                    val _data: ByteString = (json \ "data")
                      .asOpt[String]
                      .map(str => ByteString(base64decoder.decode(str)))
                      .getOrElse(ByteString.empty)
                    (port, address, Datagram(_data, remoteAddress))
                  case _                         =>
                    (0, "localhost", Datagram(ByteString.empty, remoteAddress))
                }

              val updFlow: Flow[Datagram, Datagram, Future[InetSocketAddress]] =
                UdpClient
                  .flow(new InetSocketAddress("0.0.0.0", 0))

              def nothing[T]: Flow[T, T, NotUsed] = Flow[T].map(identity)

              val flow: Flow[PlayWSMessage, PlayWSBinaryMessage, NotUsed] = fromJson via Flow
                .fromGraph(GraphDSL.create() { implicit builder =>
                  val dispatch = builder.add(
                    UnzipWith[(Int, String, Datagram), Int, String, Datagram](a => a)
                  )
                  val merge    = builder.add(
                    ZipWith[Int, String, Datagram, (Int, String, Datagram)]((a, b, c) => (a, b, c))
                  )
                  dispatch.out2 ~> updFlow.async ~> merge.in2
                  dispatch.out1 ~> nothing[String].async ~> merge.in1
                  dispatch.out0 ~> nothing[Int].async ~> merge.in0
                  FlowShape(dispatch.in, merge.out)
                })
                .map { case (port, address, dg) =>
                  PlayWSBinaryMessage(
                    ByteString(
                      Json.stringify(
                        Json.obj(
                          "port"    -> port,
                          "address" -> address,
                          "data"    -> base64encoder.encodeToString(dg.data.toArray)
                        )
                      )
                    )
                  )
                }
                .alsoTo(Sink.onComplete { case _ =>
                  promise.trySuccess(
                    ProxyDone(
                      200,
                      false,
                      0,
                      Seq.empty[Header],
                      Seq.empty[Header],
                      Seq.empty[Header]
                    )
                  )
                })
              FastFuture.successful(Right(flow))
            }
          }
        }
        case Right(httpRequest) if !descriptor.tcpUdpTunneling => {
          if (descriptor.useNewWSClient) {
            FastFuture.successful(
              Right(
                WebSocketProxyActor.wsCall(
                  UrlSanitizer.sanitize(httpRequest.url),
                  // httpRequest.headers.toSeq, //.filterNot(_._1 == "Cookie"),
                  HeadersHelper
                    .addClaims(httpRequest.headers, httpRequest.claims, descriptor),
                  descriptor,
                  httpRequest.target.getOrElse(_target)
                )
              )
            )
          } else {
            attrs.put(
              otoroshi.plugins.Keys.RequestTargetKey -> httpRequest.target
                .getOrElse(_target)
            )
            FastFuture.successful(
              Right(
                ActorFlow
                  .actorRef(out =>
                    WebSocketProxyActor.props(
                      UrlSanitizer.sanitize(httpRequest.url),
                      out,
                      httpRequest.headers.toSeq, //.filterNot(_._1 == "Cookie"),
                      descriptor,
                      None, // TODO - check if we can pass the current route
                      httpRequest.target.getOrElse(_target),
                      env
                    )
                  )
                  .alsoTo(Sink.onComplete { case _ =>
                    promise.trySuccess(
                      ProxyDone(
                        200,
                        false,
                        0,
                        headersOut = Seq.empty[Header],
                        otoroshiHeadersOut = Seq.empty[Header],
                        otoroshiHeadersIn = req.headers.toSimpleMap.map(Header.apply).toSeq
                      )
                    )
                  })
              )
            )
          }
        }
      }
  }
}

object WebSocketProxyActor {

  lazy val logger = Logger("otoroshi-websocket")

  def props(
      url: String,
      out: ActorRef,
      headers: Seq[(String, String)],
      descriptor: ServiceDescriptor,
      route: Option[NgRoute],
      target: Target,
      env: Env
  ) =
    Props(new WebSocketProxyActor(url, out, headers, descriptor, route, target, env))

  def wsCall(url: String, headers: Seq[(String, String)], descriptor: ServiceDescriptor, target: Target)(implicit
      env: Env,
      ec: ExecutionContext,
      mat: Materializer
  ): Flow[PlayWSMessage, PlayWSMessage, Future[NotUsed]] = {
    val avoid                                = Seq("Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Key")
    val _headers                             = headers.toList.filterNot(t => avoid.contains(t._1)).flatMap {
      case (key, value) if key.toLowerCase == "cookie"     =>
        Try(value.split(";").toSeq.map(_.trim).filterNot(_.isEmpty).map { cookie =>
          val parts       = cookie.split("=")
          val name        = parts(0)
          val cookieValue = parts.tail.mkString("=")
          akka.http.scaladsl.model.headers.Cookie(name, cookieValue)
        }) match {
          case Success(seq) => seq
          case Failure(e)   => List.empty
        }
      case (key, value) if key.toLowerCase == "host"       =>
        Seq(akka.http.scaladsl.model.headers.Host(value))
      case (key, value) if key.toLowerCase == "user-agent" =>
        Seq(akka.http.scaladsl.model.headers.`User-Agent`(value))
      case (key, value)                                    =>
        Seq(RawHeader(key, value))
    }
    val request                              = _headers.foldLeft[WebSocketRequest](WebSocketRequest(url))((r, header) =>
      r.copy(extraHeaders = r.extraHeaders :+ header)
    )
    val flow                                 = Flow.fromSinkAndSourceMat(
      Sink.asPublisher[akka.http.scaladsl.model.ws.Message](fanout = false),
      Source.asSubscriber[akka.http.scaladsl.model.ws.Message]
    )(Keep.both)
    val (connected, (publisher, subscriber)) = env.gatewayClient.ws(
      request = request,
      targetOpt = Some(target),
      mtlsConfigOpt = Some(target.mtlsConfig).filter(_.mtls),
      clientFlow = flow,
      //a => a
      customizer = descriptor.clientConfig.proxy
        .orElse(env.datastores.globalConfigDataStore.latestSafe.flatMap(_.proxies.services))
        .filter(p =>
          WSProxyServerUtils.isIgnoredForHost(Uri(url).authority.host.toString(), p.nonProxyHosts.getOrElse(Seq.empty))
        )
        .map { proxySettings =>
          val proxyAddress        = InetSocketAddress.createUnresolved(proxySettings.host, proxySettings.port)
          val httpsProxyTransport = (proxySettings.principal, proxySettings.password) match {
            case (Some(principal), Some(password)) => {
              val auth = akka.http.scaladsl.model.headers.BasicHttpCredentials(principal, password)
              ClientTransport.httpsProxy(proxyAddress, auth)
            }
            case _                                 => ClientTransport.httpsProxy(proxyAddress)
          }
          a: ClientConnectionSettings =>
            a.withTransport(httpsProxyTransport)
              .withIdleTimeout(descriptor.clientConfig.idleTimeout.millis)
              .withConnectingTimeout(descriptor.clientConfig.connectionTimeout.millis)
        } getOrElse { a: ClientConnectionSettings =>
        val maybeIpAddress = target.ipAddress.map(addr => InetSocketAddress.createUnresolved(addr, target.thePort))
        if (env.manualDnsResolve && maybeIpAddress.isDefined) {
          a.withTransport(ManualResolveTransport.resolveTo(maybeIpAddress.get))
            .withIdleTimeout(descriptor.clientConfig.idleTimeout.millis)
            .withConnectingTimeout(descriptor.clientConfig.connectionTimeout.millis)
        } else {
          a.withIdleTimeout(descriptor.clientConfig.idleTimeout.millis)
            .withConnectingTimeout(descriptor.clientConfig.connectionTimeout.millis)
        }
      }
    )
    Flow.lazyFutureFlow[PlayWSMessage, PlayWSMessage, NotUsed] { () =>
      connected.flatMap { r =>
        if (logger.isTraceEnabled)
          logger.trace(
            s"[WEBSOCKET] connected to target ${r.response.status} :: ${r.response.headers.map(h => h.toString()).mkString(", ")}"
          )
        r match {
          case ValidUpgrade(response, chosenSubprotocol) =>
            val f: Flow[PlayWSMessage, PlayWSMessage, NotUsed] = Flow.fromSinkAndSource(
              Sink.fromSubscriber(subscriber).contramap {
                case PlayWSTextMessage(text)      => akka.http.scaladsl.model.ws.TextMessage(text)
                case PlayWSBinaryMessage(data)    => akka.http.scaladsl.model.ws.BinaryMessage(data)
                case PingMessage(data)            => akka.http.scaladsl.model.ws.BinaryMessage(data)
                case PongMessage(data)            => akka.http.scaladsl.model.ws.BinaryMessage(data)
                case CloseMessage(status, reason) =>
                  logger.error(s"close message $status: $reason")
                  akka.http.scaladsl.model.ws.BinaryMessage(ByteString.empty)
                // throw new RuntimeException(reason)
                case m                            =>
                  logger.error(s"Unknown message $m")
                  throw new RuntimeException(s"Unknown message $m")
              },
              Source.fromPublisher(publisher).mapAsync(1) {
                case akka.http.scaladsl.model.ws.TextMessage.Strict(text)       =>
                  FastFuture.successful(PlayWSTextMessage(text))
                case akka.http.scaladsl.model.ws.TextMessage.Streamed(source)   =>
                  source.runFold("")((concat, str) => concat + str).map(str => PlayWSTextMessage(str))
                case akka.http.scaladsl.model.ws.BinaryMessage.Strict(data)     =>
                  FastFuture.successful(PlayWSBinaryMessage(data))
                case akka.http.scaladsl.model.ws.BinaryMessage.Streamed(source) =>
                  source
                    .runFold(ByteString.empty)((concat, str) => concat ++ str)
                    .map(data => PlayWSBinaryMessage(data))
                case other                                                      => FastFuture.failed(new RuntimeException(s"Unkown message type ${other}"))
              }
            )
            FastFuture.successful(f)
          case InvalidUpgradeResponse(response, cause)   =>
            FastFuture.failed(new RuntimeException(cause))
        }
      }
    }
  }
}

class WebSocketProxyActor(
    url: String,
    out: ActorRef,
    headers: Seq[(String, String)],
    descriptor: ServiceDescriptor,
    route: Option[NgRoute],
    target: Target,
    env: Env
) extends Actor {

  import scala.concurrent.duration._

  implicit val ec  = env.otoroshiExecutionContext
  implicit val mat = env.otoroshiMaterializer
  implicit val e = env

  lazy val source = Source.queue[akka.http.scaladsl.model.ws.Message](50000, OverflowStrategy.dropTail)
  lazy val logger = Logger("otoroshi-websocket-handler-actor")

  val queueRef = new AtomicReference[SourceQueueWithComplete[akka.http.scaladsl.model.ws.Message]]

  val avoid = Seq("Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Key")
  // Seq("Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Host")

  override def preStart() =
    try {
      if (logger.isTraceEnabled) logger.trace("[WEBSOCKET] initializing client call ...")
      val _headers                  = headers.toList.filterNot(t => avoid.contains(t._1)).flatMap {
        case (key, value) if key.toLowerCase == "cookie"     =>
          Try(value.split(";").toSeq.map(_.trim).filterNot(_.isEmpty).map { cookie =>
            val parts       = cookie.split("=")
            val name        = parts(0)
            val cookieValue = parts.tail.mkString("=")
            akka.http.scaladsl.model.headers.Cookie(name, cookieValue)
          }) match {
            case Success(seq) => seq
            case Failure(e)   => List.empty
          }
        case (key, value) if key.toLowerCase == "host"       =>
          Seq(akka.http.scaladsl.model.headers.Host(value.split(":").head))
        case (key, value) if key.toLowerCase == "user-agent" =>
          Seq(akka.http.scaladsl.model.headers.`User-Agent`(value))
        case (key, value)                                    =>
          Seq(RawHeader(key, value))
      }
      val request                   = _headers.foldLeft[WebSocketRequest](WebSocketRequest(url))((r, header) =>
        r.copy(extraHeaders = r.extraHeaders :+ header)
      )
      val (connected, materialized) = env.gatewayClient.ws(
        request = request,
        targetOpt = Some(target),
        mtlsConfigOpt = Some(target.mtlsConfig).filter(_.mtls),
        clientFlow = Flow
          .fromSinkAndSourceMat(
            Sink.foreach[akka.http.scaladsl.model.ws.Message] {
              case akka.http.scaladsl.model.ws.TextMessage.Strict(text)       =>
                if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] text message from target")
                out ! PlayWSTextMessage(text)
              case akka.http.scaladsl.model.ws.TextMessage.Streamed(source)   =>
                if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] streamed text message from target")
                source.runFold("")((concat, str) => concat + str).map(text => out ! PlayWSTextMessage(text))
              case akka.http.scaladsl.model.ws.BinaryMessage.Strict(data)     =>
                if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] binary message from target")
                out ! PlayWSBinaryMessage(data)
              case akka.http.scaladsl.model.ws.BinaryMessage.Streamed(source) =>
                if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] binary message from target")
                source
                  .runFold(ByteString.empty)((concat, str) => concat ++ str)
                  .map(data => out ! PlayWSBinaryMessage(data))
              case other                                                      => logger.error(s"Unkown message type ${other}")
            },
            source
          )(Keep.both)
          .alsoTo(Sink.onComplete { _ =>
            if (logger.isTraceEnabled) logger.trace(s"[WEBSOCKET] target stopped")
            Option(queueRef.get()).foreach(_.complete())
          // out ! PoisonPill
          }),
        customizer = descriptor.clientConfig.proxy
          .orElse(env.datastores.globalConfigDataStore.latestSafe.flatMap(_.proxies.services))
          .filter(p =>
            WSProxyServerUtils
              .isIgnoredForHost(Uri(url).authority.host.toString(), p.nonProxyHosts.getOrElse(Seq.empty))
          )
          .map { proxySettings =>
            val proxyAddress        = InetSocketAddress.createUnresolved(proxySettings.host, proxySettings.port)
            val httpsProxyTransport = (proxySettings.principal, proxySettings.password) match {
              case (Some(principal), Some(password)) => {
                val auth = akka.http.scaladsl.model.headers.BasicHttpCredentials(principal, password)
                ClientTransport.httpsProxy(proxyAddress, auth)
              }
              case _                                 => ClientTransport.httpsProxy(proxyAddress)
            }
            // TODO: use proxy transport when akka http will be updated
            a: ClientConnectionSettings =>
              //a //.withTransport(httpsProxyTransport)
              a.withIdleTimeout(descriptor.clientConfig.idleTimeout.millis)
                .withConnectingTimeout(descriptor.clientConfig.connectionTimeout.millis)
          } getOrElse { a: ClientConnectionSettings =>
          a.withIdleTimeout(descriptor.clientConfig.idleTimeout.millis)
            .withConnectingTimeout(descriptor.clientConfig.connectionTimeout.millis)
        }
      )
      queueRef.set(materialized._2)
      connected.andThen {
        case Success(r) => {
          implicit val ec  = env.otoroshiExecutionContext
          implicit val mat = env.otoroshiMaterializer
          if (logger.isTraceEnabled)
            logger.trace(
              s"[WEBSOCKET] connected to target ${r.response.status} :: ${r.response.headers.map(h => h.toString()).mkString(", ")}"
            )
          r.response.entity.dataBytes.runFold(ByteString.empty)(_ ++ _).map { bs =>
            if (logger.isTraceEnabled) logger.trace(s"[WEBSOCKET] connected to target with response '${bs.utf8String}'")
          }
        }
        case Failure(e) => logger.error(s"[WEBSOCKET] error", e)
      }(context.dispatcher)
    } catch {
      case e: Exception => logger.error("[WEBSOCKET] error during call", e)
    }

  override def postStop() = {
    if (logger.isTraceEnabled) logger.trace(s"[WEBSOCKET] client stopped")
    Option(queueRef.get()).foreach(_.complete())
    // out ! PoisonPill
  }

  def receive: Receive = {
    case data: play.api.http.websocket.Message => new WebsocketEngine()
      .handle(route.get, data)
      .map(_ => data match {
        case msg: PlayWSBinaryMessage     => {
          if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] binary message from client: ${msg.data.utf8String}")
          Option(queueRef.get()).foreach(_.offer(akka.http.scaladsl.model.ws.BinaryMessage(msg.data)))
        }
        case msg: PlayWSTextMessage       => {
          if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] text message from client: ${msg.data}")
          Option(queueRef.get()).foreach(_.offer(akka.http.scaladsl.model.ws.TextMessage(msg.data)))
        }
        case msg: PingMessage             => {
          if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] Ping message from client: ${msg.data}")
          Option(queueRef.get()).foreach(_.offer(akka.http.scaladsl.model.ws.BinaryMessage(msg.data)))
        }
        case msg: PongMessage             => {
          if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] Pong message from client: ${msg.data}")
          Option(queueRef.get()).foreach(_.offer(akka.http.scaladsl.model.ws.BinaryMessage(msg.data)))
        }
        case CloseMessage(status, reason) => {
          if (logger.isDebugEnabled) logger.debug(s"[WEBSOCKET] close message from client: $status : $reason")
          Option(queueRef.get()).foreach(_.complete())
          // out ! PoisonPill
        }
        case e                            => logger.error(s"[WEBSOCKET] Bad message type: $e")
      })
  }
}

class WebsocketEngine {

  def handle(route: NgRoute, data: play.api.http.websocket.Message)
            (implicit env: Env, ec: ExecutionContext): FEither[NgProxyEngineError, Done] = {
    val (requestValidators, responseValidators) = route.plugins.slots
        .filter(_.enabled)
        // .filter(_.matches(request))
        .map(inst => (inst, inst.getPlugin[NgWebsocketPlugin]))
        .collect { case (inst, Some(plugin)) =>
          NgPluginWrapper.NgSimplePluginWrapper(inst, plugin)
        }
        .partition(_.plugin.onRequestFlow)

    val _ctx = NgWebsocketPluginContext(
      snowflake = "snowflake",
      request = null,
      //      rawRequest = rawRequest,
      //      otoroshiRequest = otoroshiRequest,
      //      apikey = attrs.get(otoroshi.plugins.Keys.ApiKeyKey),
      //      user = attrs.get(otoroshi.plugins.Keys.UserKey),
      route = route,
      config = Json.obj(),
      //      globalConfig = globalConfig.plugins.config,
      attrs = null,
      report = null,
      //      sequence = sequence,
      //      markPluginItem = markPluginItem
    )

    val promise = Promise[Either[NgProxyEngineError, Done]]()

    def next(plugins: Seq[NgPluginWrapper[NgWebsocketPlugin]]): Unit = {
      plugins.headOption match {
        case None => promise.trySuccess(Right(Done))
        case Some(wrapper) => {
          val pluginConfig: JsValue = wrapper.plugin.defaultConfig
            .map(dc => dc ++ wrapper.instance.config.raw)
            .getOrElse(wrapper.instance.config.raw)
          val ctx = _ctx.copy(
            config = pluginConfig,
            //            apikey = _ctx.apikey.orElse(attrs.get(otoroshi.plugins.Keys.ApiKeyKey)),
            //            user = _ctx.user.orElse(attrs.get(otoroshi.plugins.Keys.UserKey)),
            //            idx = wrapper.instance.instanceId
          )

          wrapper.plugin.access(ctx, data match {
            case PlayWSTextMessage(data) => data
            case PlayWSBinaryMessage(data) => data.utf8String
            case CloseMessage(statusCode, reason) => ""
            case PingMessage(data) => data.utf8String
            case PongMessage(data) => data.utf8String
          }).andThen {
            case Failure(_) =>
              promise.trySuccess(
                Left(
                  NgResultProxyEngineError(Results.InternalServerError)
                )
              )
            case Success(NgAccess.NgDenied(result)) =>
              promise.trySuccess(Left(NgResultProxyEngineError(result)))
            case Success(NgAccess.NgAllowed) if plugins.size == 1 =>
              promise.trySuccess(Right(Done))
            case Success(NgAccess.NgAllowed) =>
              next(plugins.tail)
          }
        }
      }
    }

    next(requestValidators)
    FEither.apply(promise.future)
  }


}