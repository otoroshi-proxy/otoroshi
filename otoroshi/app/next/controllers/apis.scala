package otoroshi.next.controllers.adminapi

import akka.NotUsed
import akka.stream.scaladsl.Source
import next.models.{Api, ApiConsumerStatus, ApiPublished, ApiRemoved, ApiState}
import otoroshi.actions.ApiAction
import otoroshi.env.Env
import otoroshi.events.{AdminApiEvent, Audit}
import otoroshi.next.controllers.Stats
import otoroshi.utils.syntax.implicits._
import play.api.Logger
import play.api.libs.json.{JsObject, Json}
import play.api.mvc._

import java.util.concurrent.TimeUnit
import scala.concurrent.Future
import scala.concurrent.duration.FiniteDuration

class ApisController(ApiAction: ApiAction, cc: ControllerComponents)(implicit env: Env)
    extends AbstractController(cc) {

  implicit lazy val ec  = env.otoroshiExecutionContext
  implicit lazy val mat = env.otoroshiMaterializer

  lazy val logger = Logger("otoroshi-apis-controller")

  case class RouteStats(calls: Long = 0,
                        dataIn: Long = 0,
                        dataOut: Long = 0,
                        rate: Double = 0.0,
                        duration: Double = 0.0,
                        overhead: Double = 0.0,
                        dataInRate: Double = 0.0,
                        dataOutRate: Double = 0.0,
                        concurrentHandleRequests: Long = 0) {
    def json = Json.obj(
      "calls" -> calls,
      "dataIn" -> dataIn,
      "dataOut" -> dataOut,
      "rate" -> rate,
      "duration" -> duration,
      "overhead" -> overhead,
      "dataInRate" -> dataInRate,
      "dataOutRate" -> dataOutRate,
      "concurrentHandleRequests" -> concurrentHandleRequests
    )
  }

  def liveStats(id: String, every: Option[Int]) =
    ApiAction.async { ctx =>
      ctx.canReadService(id) {
        Audit.send(
          AdminApiEvent(
            env.snowflakeGenerator.nextIdStr(),
            env.env,
            Some(ctx.apiKey),
            ctx.user,
            "ACCESS_SERVICE_LIVESTATS",
            "User accessed api livestats",
            ctx.from,
            ctx.ua,
            Json.obj("apiId" -> id)
          )
        )

        def fetch(): Future[JsObject] = {
            env.datastores.apiDataStore.findById(id) flatMap  {
              case None => Json.obj().vfuture
              case Some(api) => api.toRoutes.flatMap(routes => Future.sequence(routes.map(route =>
                for {
                  calls                     <- env.datastores.serviceDescriptorDataStore.calls(route.id)
                  dataIn                    <- env.datastores.serviceDescriptorDataStore.dataInFor(route.id)
                  dataOut                   <- env.datastores.serviceDescriptorDataStore.dataOutFor(route.id)
                  rate                      <- env.datastores.serviceDescriptorDataStore.callsPerSec(route.id)
                  duration                  <- env.datastores.serviceDescriptorDataStore.callsDuration(route.id)
                  overhead                  <- env.datastores.serviceDescriptorDataStore.callsOverhead(route.id)
                  dataInRate                <- env.datastores.serviceDescriptorDataStore.dataInPerSecFor(route.id)
                  dataOutRate               <- env.datastores.serviceDescriptorDataStore.dataOutPerSecFor(route.id)
                  concurrentHandledRequests <- env.datastores.requestsDataStore.asyncGetHandledRequests()
                  membersStats              <- env.datastores.clusterStateDataStore.getMembers().map(_.map(_.statsView))
                } yield RouteStats(
                  calls                     = calls,
                  dataIn                    = dataIn,
                  dataOut                   = dataOut,
                  rate                      = Stats.sumDouble(rate, _.rate, membersStats),
                  duration                  = Stats.avgDouble(duration, _.duration, membersStats),
                  overhead                  = Stats.avgDouble(overhead, _.overhead, membersStats),
                  dataInRate                = Stats.sumDouble(dataInRate, _.dataInRate, membersStats),
                  dataOutRate               = Stats.sumDouble(dataOutRate, _.dataOutRate, membersStats),
                  Stats.sumDouble(
                    concurrentHandledRequests.toDouble,
                    _.concurrentHandledRequests.toDouble,
                    membersStats
                  ).toLong
                )
              ))).map(stats => stats.foldLeft(RouteStats()) { case (acc, item) => acc.copy(
                calls  = acc.calls + item.calls,
                dataIn  = acc.dataIn + item.dataIn,
                dataOut  = acc.dataOut + item.dataOut,
                rate  = acc.rate + item.rate,
                duration  = acc.duration + item.duration,
                overhead  = acc.overhead + item.overhead,
                dataInRate  = acc.dataInRate + item.dataInRate,
                dataOutRate  = acc.dataOutRate + item.dataOutRate,
                concurrentHandleRequests = acc.concurrentHandleRequests + item.concurrentHandleRequests
              )}.json)
            }
        }

        every match {
          case Some(millis) =>
            Ok.chunked(
                Source
                  .tick(FiniteDuration(0, TimeUnit.MILLISECONDS), FiniteDuration(millis, TimeUnit.MILLISECONDS), NotUsed)
                  .flatMapConcat(_ => Source.future(fetch()))
                  .map(json => s"data: ${Json.stringify(json)}\n\n")
              ).as("text/event-stream")
              .future
          case None         =>
            Ok.chunked(Source.single(1).flatMapConcat(_ => Source.future(fetch()))).as("application/json").future
        }
      }
    }


  def start(id: String) = {
    ApiAction.async { ctx =>
      ctx.canReadService(id) {
        Audit.send(
          AdminApiEvent(
            env.snowflakeGenerator.nextIdStr(),
            env.env,
            Some(ctx.apiKey),
            ctx.user,
            "ACCESS_SERVICE_APIS",
            "User started the api",
            ctx.from,
            ctx.ua,
            Json.obj("apiId" -> id)
          )
        )

        toggleApiRoutesStatus(id, newStatus = true)
      }
    }
  }

  def toggleApiRoutesStatus(apiId: String, newStatus: Boolean): Future[Result] = {
    env.datastores.apiDataStore.findById(apiId).flatMap {
      case Some(api) => env.datastores.apiDataStore.set(api.copy(
          state = ApiPublished,
          routes = api.routes.map(route => route.copy(enabled = newStatus))))
        .flatMap(_ => Results.Ok.future)
      case None      => Results.NotFound.future
    }
  }

  def stop(id: String) = {
    ApiAction.async { ctx =>
      ctx.canReadService(id) {
        Audit.send(
          AdminApiEvent(
            env.snowflakeGenerator.nextIdStr(),
            env.env,
            Some(ctx.apiKey),
            ctx.user,
            "ACCESS_SERVICE_APIS",
            "User stopped the api",
            ctx.from,
            ctx.ua,
            Json.obj("apiId" -> id)
          )
        )

        toggleApiRoutesStatus(id, newStatus = false)
      }
    }
  }

  def publishConsumer(apiId: String, consumerId: String): Action[AnyContent] = {
    ApiAction.async { ctx =>
      ctx.canReadService(apiId) {
        Audit.send(
          AdminApiEvent(
            env.snowflakeGenerator.nextIdStr(),
            env.env,
            Some(ctx.apiKey),
            ctx.user,
            "ACCESS_SERVICE_API_CONSUMER",
            "User published the consumer",
            ctx.from,
            ctx.ua,
            Json.obj("apiId" -> apiId, "consumerId" -> consumerId)
          )
        )

        updateConsumerStatus(apiId, consumerId, ApiConsumerStatus.Published)
      }
    }
  }

  def updateConsumerStatus(apiId: String, consumerId: String, status: ApiConsumerStatus): Future[Result] = {
    env.datastores.apiDataStore.findById(apiId).flatMap {
      case Some(api) =>
        var result: Option[String] = Some("")
        val newAPI = api.copy(consumers = api.consumers.map(consumer => {
          if(consumer.id == consumerId) {
            if (Api.updateConsumerStatus(consumer, consumer.copy(status = status))) {
              consumer.copy(status = status)
            } else {
              result = None
              consumer
            }
          } else {
            consumer
          }
        }))

        result match {
          case None => Results.BadRequest(Json.obj("error" -> "you can't update consumer status")).future
          case Some(_) => env.datastores.apiDataStore.set(newAPI)
            .flatMap(_ => Results.Ok.vfuture)
        }
      case None      => Results.NotFound.future
    }
  }

  def deprecateConsumer(apiId: String, consumerId: String) = {
    ApiAction.async { ctx =>
      ctx.canReadService(apiId) {
        Audit.send(
          AdminApiEvent(
            env.snowflakeGenerator.nextIdStr(),
            env.env,
            Some(ctx.apiKey),
            ctx.user,
            "ACCESS_SERVICE_API_CONSUMER",
            "User deprecated the consumer",
            ctx.from,
            ctx.ua,
            Json.obj("apiId" -> apiId, "consumerId" -> consumerId)
          )
        )

        updateConsumerStatus(apiId, consumerId, ApiConsumerStatus.Deprecated)
      }
    }
  }

  def closeConsumer(apiId: String, consumerId: String) = {
    ApiAction.async { ctx =>
      ctx.canReadService(apiId) {
        Audit.send(
          AdminApiEvent(
            env.snowflakeGenerator.nextIdStr(),
            env.env,
            Some(ctx.apiKey),
            ctx.user,
            "ACCESS_SERVICE_API_CONSUMER",
            "User deprecated the consumer",
            ctx.from,
            ctx.ua,
            Json.obj("apiId" -> apiId, "consumerId" -> consumerId)
          )
        )

        updateConsumerStatus(apiId, consumerId, ApiConsumerStatus.Closed)
      }
    }
  }
}
