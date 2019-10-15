package controllers

import actions.{ApiAction, PrivateAppsAction}
import akka.util.ByteString
import auth.{BasicAuthModule, BasicAuthUser}
import env.Env
import org.mindrot.jbcrypt.BCrypt
import play.api.libs.json.Json
import play.api.mvc._
import security.IdGenerator

import scala.concurrent.Future
import utils.future.Implicits._

class PrivateAppsController(ApiAction: ApiAction, PrivateAppsAction: PrivateAppsAction, cc: ControllerComponents)(implicit env: Env)
    extends AbstractController(cc) {

  implicit lazy val ec  = env.otoroshiExecutionContext
  implicit lazy val mat = env.otoroshiMaterializer

  def home = PrivateAppsAction { ctx =>
    Ok(views.html.privateapps.home(ctx.user, env))
  }

  def redirect = PrivateAppsAction { ctx =>
    implicit val request = ctx.request
    Redirect(
      //request.session
      //  .get("pa-redirect-after-login")
      //  .getOrElse(
      routes.PrivateAppsController.home().absoluteURL(env.exposedRootSchemeIsHttps)
      //  )
    ) //.removingFromSession("pa-redirect-after-login")
  }

  def error(message: Option[String] = None) = PrivateAppsAction { ctx =>
    Ok(views.html.otoroshi.error(message.getOrElse(""), env))
  }

  def withShortSession(req: RequestHeader)(f: (BasicAuthModule, BasicAuthUser) => Future[Result]): Future[Result] = {
    req.getQueryString("session") match {
      case None => NotFound( Json.obj("error" -> s"session not found")).future
      case Some(sessionId) => {
        env.datastores.rawDataStore.get(s"${env.rootScheme}:self-service:sessions:$sessionId").flatMap {
          case None => NotFound( Json.obj("error" -> s"session not found")).future
          case Some(sessionRaw) => {
            val session = Json.parse(sessionRaw.utf8String)
            val username = (session \ "username").as[String]
            val id = (session \ "auth").as[String]
            env.datastores.authConfigsDataStore.findById(id).flatMap {
              case Some(auth) => {
                auth.authModule(env.datastores.globalConfigDataStore.latest()) match {
                  case bam: BasicAuthModule if bam.authConfig.webauthn => {
                    bam.authConfig.users.find(_.email == username) match {
                      case None => NotFound( Json.obj("error" -> s"user not found")).future
                      case Some(user) => {
                        f(bam, user)
                      }
                    }
                  }
                  case _ => BadRequest(Json.obj("error" -> s"Not supported")).future
                }
              }
              case None =>
                NotFound(
                  Json.obj("error" -> s"GlobalAuthModule with id $id not found")
                ).future
            }
          }
        }
      }
    }
  }

  def registerSession(authModuleId: String, username: String) = ApiAction.async { ctx =>
    import scala.concurrent.duration._
    val sessionId = IdGenerator.token(32)
    env.datastores.rawDataStore.set(s"${env.rootScheme}:self-service:sessions:$sessionId", ByteString(Json.stringify(Json.obj(
      "username" -> username,
      "auth" -> authModuleId
    ))), Some(10.minutes.toMillis)).map { _ =>
      val host = "http://" + env.privateAppsHost + env.privateAppsPort.map(p => ":" + p).getOrElse("")
      Ok(Json.obj("sessionId" -> sessionId, "host" -> host))
    }
  }

  def selfRegistrationStart() = Action.async { req =>
    withShortSession(req) {
      case (bam, _) =>
        bam.webAuthnRegistrationStart(req.body.asJson.get).map {
          case Left(err) => BadRequest(err)
          case Right(reg) => Ok(reg)
      }
    }
  }

  def selfRegistrationFinish() = Action.async { req =>
    withShortSession(req) {
      case (bam, _) =>
        bam.webAuthnRegistrationFinish(req.body.asJson.get).map {
          case Left(err) => BadRequest(err)
          case Right(reg) => Ok(reg)
        }
    }
  }

  def selfUpdateProfilePage() = Action.async { req =>
    withShortSession(req) {
      case (bam, user) =>
        Ok(views.html.otoroshi.selfUpdate(Json.obj(
          "name" -> user.name,
          "email" -> user.email
        ), req.getQueryString("session").get, bam.authConfig.webauthn, env)).future
    }
  }

  def selfUpdateProfile() = Action.async(parse.json) { req =>
    withShortSession(req) {
      case (bam, user) =>
        var newUser = user
        (req.body \ "name").asOpt[String].foreach(name => newUser = newUser.copy(name = name))
        (req.body \ "password").asOpt[String].foreach(password => newUser = newUser.copy(password = BCrypt.hashpw(password, BCrypt.gensalt(10))))
        val conf = bam.authConfig.copy(users = bam.authConfig.users.filterNot(_.email == user.email) :+ newUser)
        conf.save().map { _ =>
          Ok(Json.obj(
            "name" -> newUser.name,
            "email" -> newUser.email
          ))
        }
    }
  }
}
