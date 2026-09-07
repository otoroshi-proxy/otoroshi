package functional

import org.scalatest.OptionValues
import otoroshi.auth.LdapAuthModuleConfig

// pure logic: the search filter is built by substituting the login into a configured template, and a
// login is attacker controlled input
class LdapFilterSpec
    extends org.scalatest.wordspec.AnyWordSpec
    with org.scalatest.matchers.must.Matchers
    with OptionValues {

  // a restrictive filter is the common shape: injecting into it lets a caller add conditions of its
  // own, which is an oracle to probe the directory blindly
  val restrictiveFilter = "(&(mail=${username})(department=IT))"

  "LDAP search filter building" should {

    "substitute the username" in {
      LdapAuthModuleConfig.searchFilterFor("(mail=${username})", "user@oto.tools") mustBe "(mail=user@oto.tools)"
    }

    "not let a wildcard match every user" in {
      LdapAuthModuleConfig.searchFilterFor("(mail=${username})", "*") mustBe "(mail=\\2a)"
    }

    "not let parenthesis inject extra conditions into the filter" in {
      val filter = LdapAuthModuleConfig.searchFilterFor(restrictiveFilter, "*)(objectClass=*")
      filter mustBe "(&(mail=\\2a\\29\\28objectClass=\\2a)(department=IT))"
    }

    "not let a backslash smuggle an escape sequence" in {
      LdapAuthModuleConfig.searchFilterFor("(mail=${username})", "a\\2a") mustBe "(mail=a\\5c2a)"
    }

    "escape the nul character" in {
      LdapAuthModuleConfig.searchFilterFor("(mail=${username})", "a\u0000b") mustBe "(mail=a\\00b)"
    }

    "leave an ordinary login untouched" in {
      LdapAuthModuleConfig.searchFilterFor(restrictiveFilter, "jane.doe@oto.tools") mustBe
        "(&(mail=jane.doe@oto.tools)(department=IT))"
    }
  }
}
