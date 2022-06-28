package otoroshi.next.plugins

import akka.stream.Materializer
import akka.stream.scaladsl.Source
import akka.util.ByteString
import otoroshi.env.Env
import otoroshi.next.plugins.api._
import otoroshi.next.proxy.NgProxyEngineError
import otoroshi.utils.http.RequestImplicits.EnhancedRequestHeader
import otoroshi.utils.syntax.implicits._
import play.api.libs.json._

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Either, Failure, Success, Try}

case class StaticResponseConfig(status: Int = 200, headers: Map[String, String] = Map.empty, body: String = "")
    extends NgPluginConfig {
  def json: JsValue = StaticResponseConfig.format.writes(this)
}

object StaticResponseConfig {
  val format = new Format[StaticResponseConfig] {
    override def writes(o: StaticResponseConfig): JsValue             = Json.obj(
      "status"  -> o.status,
      "headers" -> o.headers,
      "body"    -> o.body
    )
    override def reads(json: JsValue): JsResult[StaticResponseConfig] = Try {
      StaticResponseConfig(
        status = json.select("status").asOpt[Int].getOrElse(200),
        headers = json.select("headers").asOpt[Map[String, String]].getOrElse(Map.empty),
        body = json.select("body").asOpt[String].getOrElse("")
      )
    } match {
      case Failure(ex)    => JsError(ex.getMessage())
      case Success(value) => JsSuccess(value)
    }
  }
}

class StaticResponse extends NgBackendCall {

  override def useDelegates: Boolean                       = false
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = true
  override def name: String                                = "Static Response"
  override def description: Option[String]                 = "This plugin returns static responses".some
  override def defaultConfigObject: Option[NgPluginConfig] = StaticResponseConfig().some

  override def visibility: NgPluginVisibility    = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory] = Seq(NgPluginCategory.TrafficControl)
  override def steps: Seq[NgStep]                = Seq(NgStep.CallBackend)

  override def callBackend(
      ctx: NgbBackendCallContext,
      delegates: () => Future[Either[NgProxyEngineError, BackendCallResponse]]
  )(implicit
      env: Env,
      ec: ExecutionContext,
      mat: Materializer
  ): Future[Either[NgProxyEngineError, BackendCallResponse]] = {
    val config           = ctx.cachedConfig(internalName)(StaticResponseConfig.format).getOrElse(StaticResponseConfig())
    val body: ByteString = config.body match {
      case str if str.startsWith("Base64(") => str.substring(7).init.byteString.decodeBase64
      case str                              => str.byteString
    }
    bodyResponse(config.status, config.headers, Source.single(body)).future
  }
}

case class MockResponse(
    path: String = "/",
    method: String = "GET",
    status: Int = 200,
    headers: Map[String, String] = Map.empty,
    body: String = ""
) extends NgPluginConfig {
  def json: JsValue = MockResponse.format.writes(this)
}

object MockResponse {
  val format = new Format[MockResponse] {
    override def writes(o: MockResponse): JsValue             = Json.obj(
      "path"    -> o.path,
      "method"  -> o.method,
      "status"  -> o.status,
      "headers" -> o.headers,
      "body"    -> o.body
    )
    override def reads(json: JsValue): JsResult[MockResponse] = Try {
      MockResponse(
        path = json.select("path").asOpt[String].getOrElse("/"),
        method = json.select("method").asOpt[String].getOrElse("GET"),
        status = json.select("status").asOpt[Int].getOrElse(200),
        headers = json.select("headers").asOpt[Map[String, String]].getOrElse(Map.empty),
        body = json.select("body").asOpt[String].getOrElse("")
      )
    } match {
      case Failure(ex)    => JsError(ex.getMessage())
      case Success(value) => JsSuccess(value)
    }
  }
}

case class MockField(fieldName: String, fieldType: String, value: JsValue)
case class MockResource(name: String, schema: Seq[MockField] = Seq.empty, additionalData: Option[JsObject] = None)
case class MockEndpoint(method: String,
                        path: String,
                        status: Int,
                        body: Option[JsObject] = None,
                        resource: Option[String] = None,
                        resourceList: Boolean = false,
                        headers: Option[JsObject] = None)
case class MockFormData(resources: Seq[MockResource] = Seq.empty, endpoints: Seq[MockEndpoint] = Seq.empty)

object MockField {
  val format = new Format[MockField] {
    override def writes(o: MockField): JsValue = Json.obj(
    "field_name" -> o.fieldName,
      "field_type" -> o.fieldType,
      "value" -> o.value
    )

    override def reads(json: JsValue): JsResult[MockField] = Try {
      MockField(
        fieldName = json.select("field_name").as[String],
        fieldType = json.select("field_type").as[String],
        value = json.select("value").as[JsValue]
      )
    } match {
      case Failure(ex) => JsError(ex.getMessage)
      case Success(value) => JsSuccess(value)
    }
  }
}

object MockResource {
  val format = new Format[MockResource] {
    override def writes(o: MockResource): JsValue = Json.obj(
      "name" -> o.name,
      "schema" -> JsArray(o.schema.map(MockField.format.writes)),
      "additional_data" -> o.additionalData
    )
    override def reads(json: JsValue): JsResult[MockResource] = Try {
      MockResource(
        name = json.select("name").as[String],
        schema = json
          .select("schema")
          .asOpt[Seq[JsValue]]
          .map(arr => arr.flatMap(v => MockField.format.reads(v).asOpt))
          .getOrElse(Seq.empty),
        additionalData = json.select("additional_data").asOpt[JsObject]
      )
    } match {
      case Failure(ex)    => JsError(ex.getMessage)
      case Success(value) => JsSuccess(value)
    }
  }
}

object MockEndpoint {
  val format = new Format[MockEndpoint] {
    override def writes(o: MockEndpoint): JsValue             = Json.obj(
      "method"    -> o.method,
      "path" -> o.path,
      "status" -> o.status,
      "body" -> o.body,
      "resource" -> o.resource,
      "resource_list" -> o.resourceList,
      "headers" -> o.headers
    )
    override def reads(json: JsValue): JsResult[MockEndpoint] = Try {
      MockEndpoint(
        method = json.select("method").as[String],
        path = json.select("path").as[String],
        status = json.select("status").as[Int],
        body = json.select("body").asOpt[JsObject],
        resource = json.select("resource").asOpt[String],
        resourceList = json.select("resourceList").as[Boolean],
        headers = json.select("headers").asOpt[JsObject],
      )
    } match {
      case Failure(ex)    => JsError(ex.getMessage)
      case Success(value) => JsSuccess(value)
    }
  }
}

object MockFormData {
  val format = new Format[MockFormData] {
    override def writes(o: MockFormData): JsValue             = Json.obj(
      "resources"    -> JsArray(o.resources.map(MockResource.format.writes)),
      "endpoints" -> JsArray(o.endpoints.map(MockEndpoint.format.writes))
    )
    override def reads(json: JsValue): JsResult[MockFormData] = Try {
      MockFormData(
        resources = json
          .select("resources")
          .asOpt[Seq[JsValue]]
          .map(arr => arr.flatMap(v => MockResource.format.reads(v).asOpt))
          .getOrElse(Seq.empty),
        endpoints = json
          .select("endpoints")
          .asOpt[Seq[JsValue]]
          .map(arr => arr.flatMap(v => MockEndpoint.format.reads(v).asOpt))
          .getOrElse(Seq.empty)
      )
    } match {
      case Failure(ex)    => JsError(ex.getMessage)
      case Success(value) => JsSuccess(value)
    }
  }
}

case class MockResponsesConfig(
                                responses: Seq[MockResponse] = Seq.empty,
                                passThrough: Boolean = true,
                                formData: Option[MockFormData] = None
                              )
    extends NgPluginConfig {
  def json: JsValue = MockResponsesConfig.format.writes(this)
}

object MockResponsesConfig {
  val format = new Format[MockResponsesConfig] {
    override def writes(o: MockResponsesConfig): JsValue             = Json.obj(
      "responses"    -> JsArray(o.responses.map(_.json)),
      "pass_through" -> o.passThrough
    )
    override def reads(json: JsValue): JsResult[MockResponsesConfig] = Try {
      MockResponsesConfig(
        responses = json
          .select("responses")
          .asOpt[Seq[JsValue]]
          .map(arr => arr.flatMap(v => MockResponse.format.reads(v).asOpt))
          .getOrElse(Seq.empty),
        passThrough = json.select("pass_through").asOpt[Boolean].getOrElse(true),
        formData = json.select("form_data").asOpt[MockFormData](MockFormData.format.reads)
      )
    } match {
      case Failure(ex)    => JsError(ex.getMessage)
      case Success(value) => JsSuccess(value)
    }
  }
}

class MockResponses extends NgBackendCall {

  override def useDelegates: Boolean                       = true
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = true
  override def name: String                                = "Mock Responses"
  override def description: Option[String]                 = "This plugin returns mock responses".some
  override def defaultConfigObject: Option[NgPluginConfig] = MockResponsesConfig().some

  override def visibility: NgPluginVisibility    = NgPluginVisibility.NgUserLand
  override def categories: Seq[NgPluginCategory] = Seq(NgPluginCategory.TrafficControl)
  override def steps: Seq[NgStep]                = Seq(NgStep.CallBackend)

  override def callBackend(
      ctx: NgbBackendCallContext,
      delegates: () => Future[Either[NgProxyEngineError, BackendCallResponse]]
  )(implicit
      env: Env,
      ec: ExecutionContext,
      mat: Materializer
  ): Future[Either[NgProxyEngineError, BackendCallResponse]] = {
    /*
    NgTreeRouter.build(paths.map(resp => NgFakeRoute.routeFromPath(resp.path)))
        .find("", ctx.request.path)*/
    val config = ctx.cachedConfig(internalName)(MockResponsesConfig.format).getOrElse(MockResponsesConfig())
    config.responses.filter(r => r.method.toLowerCase == ctx.request.method.toLowerCase || r.method.toLowerCase == ctx.rawRequest.method.toLowerCase).find { resp =>
      resp.path.wildcard.matches(ctx.rawRequest.thePath) || resp.path.wildcard.matches(ctx.request.path)
    } match {
      case None if !config.passThrough =>
        bodyResponse(
          404,
          Map("Content-Type" -> "application/json"),
          Source.single(Json.obj("error" -> "resource not found !").stringify.byteString)
        ).future
      case None if config.passThrough  => delegates()
      case Some(response)              => {
        // val contentType      = response.headers
        //   .get("Content-Type")
        //   .orElse(response.headers.get("content-type"))
        //   .getOrElse("application/json")
        // val headers          = response.headers.filterNot(_._1.toLowerCase() == "content-type") ++ ("Content-Type" -> contentType)
        val body: ByteString = response.body match {
          case str if str.startsWith("Base64(") => str.substring(7).init.byteString.decodeBase64
          case str                              => str.byteString
        }
        bodyResponse(response.status, response.headers, Source.single(body)).future
      }
    }
  }
}
