package storage.inmemory

import env.Env
import events.{HealthCheckDataStore, HealthCheckEvent}
import models.ServiceDescriptor
import play.api.libs.json.Json
import storage.RedisLike

import scala.concurrent.{ExecutionContext, Future}

class InMemoryHealthCheckDataStore(redisCli: RedisLike, _env: Env) extends HealthCheckDataStore {

  val collectionSize = 30

  def key(name: String) = s"${_env.storageRoot}:deschealthcheck:$name"

  override def push(evt: HealthCheckEvent)(implicit ec: ExecutionContext, env: Env): Future[Long] =
    for {
      n <- redisCli.lpush(key(evt.`@serviceId`), Json.stringify(evt.toJson))
      _ <- redisCli.ltrim(key(evt.`@serviceId`), 0, collectionSize)
    } yield n

  override def findAll(serviceDescriptor: ServiceDescriptor)(implicit ec: ExecutionContext,
                                                             env: Env): Future[Seq[HealthCheckEvent]] =
    redisCli
      .lrange(key(serviceDescriptor.id), 0, collectionSize - 1)
      .map(seq => seq.map(i => Json.parse(i.utf8String).as(HealthCheckEvent.format)))

  override def findLast(serviceDescriptor: ServiceDescriptor)(implicit ec: ExecutionContext,
                                                              env: Env): Future[Option[HealthCheckEvent]] =
    redisCli
      .lrange(key(serviceDescriptor.id), 0, 1)
      .map(seq => seq.map(i => Json.parse(i.utf8String).as(HealthCheckEvent.format)).headOption)
}
