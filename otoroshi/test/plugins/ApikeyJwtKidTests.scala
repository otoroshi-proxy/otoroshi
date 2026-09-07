package plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import functional.PluginsTestSpecBase
import otoroshi.models.{ApiKey, RouteIdentifier}
import otoroshi.next.models.{NgPluginInstance, NgPluginInstanceConfig}
import otoroshi.next.plugins.api.NgPluginHelper
import otoroshi.next.plugins.{ApikeyCalls, NgApikeyCallsConfig, OverrideHost}
import otoroshi.ssl.Cert
import otoroshi.ssl.pki.models.GenCsrQuery
import play.api.http.Status
import play.api.libs.json.JsObject

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import scala.concurrent.duration.DurationInt

// the `kid` of an apikey jwt is picked by whoever signs the token, and the lookup that follows spans
// the whole certificate store. anybody able to get a certificate of their own in there can therefore
// designate it as the verification key of an apikey that pins none
class ApikeyJwtKidTests(parent: PluginsTestSpecBase, pinnedKeyPairOnly: Boolean) {
  import parent.*

  val suffix = if (pinnedKeyPairOnly) "pinned" else "open"

  val attackerCert: Cert = {
    val cert = env.pki
      .genSelfSignedCert(GenCsrQuery(hosts = Seq(s"attacker-$suffix.oto.tools"), subject = Some(s"CN=attacker")))
      .futureValue
      .toOption
      .get
      .toCert
      .copy(id = s"attacker-keypair-$suffix", name = s"attacker-$suffix")
      .enrich()
    cert.save()(using env.otoroshiExecutionContext, env).futureValue
    cert
  }

  val route = createRouteWithExternalTarget(
    Seq(
      NgPluginInstance(plugin = NgPluginHelper.pluginId[OverrideHost]),
      NgPluginInstance(
        plugin = NgPluginHelper.pluginId[ApikeyCalls],
        config = NgPluginInstanceConfig(NgApikeyCallsConfig().json.as[JsObject])
      )
    )
  ).futureValue

  // no `jwt-sign-keypair`: nothing tells otoroshi which keypair this apikey signs with
  val apikey = ApiKey(
    clientId = s"jwt-kid-apikey-$suffix",
    clientSecret = "the-real-secret",
    clientName = s"jwt kid apikey $suffix",
    authorizedEntities = Seq(RouteIdentifier(route.id))
  )

  createOtoroshiApiKey(apikey).futureValue

  // the certificate store is fed from the proxy state, which syncs periodically: wait for the
  // certificate to actually be reachable rather than assume it is
  def certInStore: Boolean = otoroshi.ssl.DynamicSSLEngineProvider.certificates.contains(attackerCert.id)
  var waited               = 0
  while (!certInStore && waited < 30) {
    await(500.millis)
    waited += 1
  }
  withClue(s"attacker certificate ${attackerCert.id} never showed up in the store ") {
    certInStore mustBe true
  }

  val keyPair = attackerCert.cryptoKeyPair

  val token = JWT
    .create()
    .withKeyId(attackerCert.id)
    .withClaim("clientId", apikey.clientId)
    .sign(
      Algorithm.RSA256(
        keyPair.getPublic.asInstanceOf[RSAPublicKey],
        keyPair.getPrivate.asInstanceOf[RSAPrivateKey]
      )
    )

  val response = ws
    .url(s"http://127.0.0.1:$port/api")
    .withHttpHeaders(
      "Host"         -> route.frontend.domains.head.domain,
      "Otoroshi-Token" -> token
    )
    .get()
    .futureValue

  withClue(s"pinnedKeyPairOnly=$pinnedKeyPairOnly status=${response.status} body=${response.body} ") {
    if (pinnedKeyPairOnly) {
      // the apikey pins no keypair, so a keypair signed token can no longer be verified for it
      response.status mustBe Status.UNAUTHORIZED
    } else {
      // the kid of the token designated the key, and it verified
      response.status mustBe Status.OK
    }
  }

  deleteOtoroshiApiKey(apikey)
  deleteOtoroshiRoute(route).futureValue
}
