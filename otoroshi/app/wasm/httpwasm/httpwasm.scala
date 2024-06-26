package otoroshi.wasm.httpwasm

import akka.stream.Materializer
import io.otoroshi.wasm4s.scaladsl._
import org.extism.sdk.wasmotoroshi._
import org.extism.sdk.{HostFunction, HostUserData}
import otoroshi.env.Env
import otoroshi.gateway.Errors
import otoroshi.next.plugins.api._
import otoroshi.utils.TypedMap
import otoroshi.utils.syntax.implicits._
import otoroshi.wasm._
import play.api._
import play.api.libs.json._
import play.api.libs.typedmap.TypedKey
import play.api.mvc.Results.{BadRequest, Status}

import java.util.concurrent.atomic._
import scala.concurrent._
import scala.util._

object HttpWasmPluginKeys {
  val HttpWasmVmKey = TypedKey[WasmVm]("otoroshi.next.plugins.HttpWasmVm")
}

class HttpWasmPlugin(wasm: WasmConfig, key: String, env: Env) {

  private implicit val ev = env
  private implicit val ec = env.otoroshiExecutionContext
  private implicit val ma = env.otoroshiMaterializer

  private lazy val state            = new HttpWasmState(env)
  private lazy val pool: WasmVmPool = WasmVmPool.forConfigurationWithId(key, wasm)(env.wasmIntegration.context)

  def createFunctions(ref: AtomicReference[WasmVmData]): Seq[HostFunction[_ <: HostUserData]] = {
    HttpWasmFunctions.build(state, ref)
  }

  def start(attrs: TypedMap): Future[Unit] = {
    pool
      .getPooledVm(
        WasmVmInitOptions(
          importDefaultHostFunctions = false,
          resetMemory = true,
          addHostFunctions = createFunctions
        )
      )
      .flatMap { vm =>
        attrs.put(otoroshi.wasm.httpwasm.HttpWasmPluginKeys.HttpWasmVmKey -> vm)
        vm.finitialize {
          Future.successful(())
        }
      }
  }

}

class NgHttpWasm extends NgRequestTransformer {

  override def steps: Seq[NgStep]                          = Seq(NgStep.TransformRequest, NgStep.TransformResponse)
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.Wasm)
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = true
  override def name: String                                = "Http WASM"
  override def description: Option[String]                 = "Http WASM plugin".some
  override def defaultConfigObject: Option[NgPluginConfig] = WasmConfig().some

  override def isTransformRequestAsync: Boolean  = true
  override def isTransformResponseAsync: Boolean = true
  override def usesCallbacks: Boolean            = true
  override def transformsRequest: Boolean        = true
  override def transformsResponse: Boolean       = true
  override def transformsError: Boolean          = false

  override def beforeRequest(
      ctx: NgBeforeRequestContext
  )(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Unit] = {
    val config = WasmConfig.format.reads(ctx.config).getOrElse(WasmConfig())
    new HttpWasmPlugin(config.copy(wasi = true), "http-wasm", env).start(ctx.attrs)
  }

  private def handleResponse(vm: WasmVm, vmData: HttpWasmVmData, reqCtx: Int, isError: Int)(implicit
      env: Env,
      ec: ExecutionContext
  ) = {
    vmData.afterNext = true
    vm.call(
      WasmFunctionParameters.NoResult("handle_response", new Parameters(2).pushInts(reqCtx, isError)),
      vmData.some
    )
  }

  private def execute(vm: WasmVm, ctx: NgTransformerRequestContext)(implicit
      env: Env,
      ec: ExecutionContext
  ): Future[Either[mvc.Result, NgPluginHttpRequest]] = {
    val vmData = HttpWasmVmData
      .withRequest(ctx.otoroshiRequest)
      .some

    vmData.get.remoteAddress = ctx.request.remoteAddress.some

    vm.callWithParamsAndResult("handle_request", new Parameters(0), 1, None, vmData)
      .flatMap {
        case Left(error) => {
          Errors
            .craftResponseResult(
              error.toString(),
              Status(401),
              ctx.request,
              None,
              None,
              attrs = TypedMap.empty
            )
            .map(r => Left(r))
        }
        case Right(res)  =>
          if (res.results.getLength > 0) {
            val ctxNext = res.results.getValue(0).v.i64

            val data = vmData.get

            val reqCtx = ctxNext >> 32
            val next   = ctxNext & 0x1

            println(s"reqCtx $reqCtx next $next")

            if (next == 0L) {
              Left(data.response.asResult).future
            } else {
              handleResponse(vm, data, reqCtx.toInt, 0)

              Right(
                ctx.otoroshiRequest.copy(
                  headers = data.request.headers,
                  url = data.request.url,
                  method = data.request.method,
                  body = data.request.body
                )
              ).future
            }
          } else {
            Left(BadRequest(Json.obj("error" -> "missing handle request result"))).future
          }
      }
  }

  override def transformRequest(
      ctx: NgTransformerRequestContext
  )(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[mvc.Result, NgPluginHttpRequest]] = {
    ctx.attrs.get(otoroshi.wasm.httpwasm.HttpWasmPluginKeys.HttpWasmVmKey) match {
      case None     => Future.failed(new RuntimeException("no vm found in attrs"))
      case Some(vm) => execute(vm, ctx)
    }
  }

  override def afterRequest(
      ctx: NgAfterRequestContext
  )(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Unit] = {
    ctx.attrs.get(otoroshi.wasm.httpwasm.HttpWasmPluginKeys.HttpWasmVmKey).foreach(_.release())
    ().vfuture
  }

  // TODO - only useful for testing
//  override def transformResponse(
//                         ctx: NgTransformerResponseContext
//                       )(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpResponse]] = {
//    ctx.attrs.get(otoroshi.wasm.httpwasm.HttpWasmPluginKeys.HttpWasmVmKey) match {
//      case None =>
//        println("no vm found in attrs")
//        Future.failed(new RuntimeException("no vm found in attrs"))
//      case Some(vm) =>
//        val vmData = HttpWasmVmData
//          .withRequest(NgPluginHttpRequest(
//            headers = ctx.otoroshiResponse.headers,
//            url = ctx.request.uri,
//            method = ctx.request.method,
//            version = ctx.request.version,
//            clientCertificateChain = () => None,
//            cookies = Seq.empty,
//            body = Source.empty,
//            backend = None
//          ))
//        vmData.remoteAddress = ctx.request.remoteAddress.some
//        vmData.response = vmData.response.copy(
//          headers = ctx.otoroshiResponse.headers,
//          status = ctx.otoroshiResponse.status,
//          cookies = ctx.otoroshiResponse.cookies,
//          body = ctx.otoroshiResponse.body
//        )
//
//        vm.callWithParamsAndResult("handle_request",
//          new Parameters(0),
//          1,
//          None,
//          vmData.some
//        )
//          .flatMap {
//            case Left(error) => {
//              Errors.craftResponseResult(
//                error.toString(),
//                Status(401),
//                ctx.request,
//                None,
//                None,
//                attrs = TypedMap.empty
//              ).map(r => Left(r))
//            }
//            case Right(res) =>
//              if(res.results.getLength() > 0){
//                val ctxNext = res.results.getValue(0).v.i64
//
//                val data = vmData
//                if ((ctxNext & 0x1) != 0x1) {
//                  Left(data.response.asResult).future
//                } else {
//                  data.nextCalled = true
//
//                  val reqCtx = ctxNext >> 32
//                  handleResponse(vm, data, reqCtx.toInt, 0)
//
//                  implicit val mat = env.otoroshiMaterializer
//
//                  if (data.request.hasBody) {
//                    Right(ctx.otoroshiResponse.copy(
//                      headers = data.response.headers,
//                      status = data.response.status,
//                      cookies = data.response.cookies,
//                      body = data.response.body,
//                    )).future
//                  } else {
//                    Right(ctx.otoroshiResponse.copy(
//                      headers = data.response.headers,
//                      status = data.response.status,
//                      cookies = data.response.cookies
//                    )).future
//                  }
//                }
//              } else {
//                println("missing handle request result")
//                Left(BadRequest(Json.obj("error" -> "missing handle request result"))).future
//              }
//          }
//    }
//  }
}
