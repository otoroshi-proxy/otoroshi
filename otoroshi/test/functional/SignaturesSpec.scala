package functional

import org.scalatest.OptionValues
import otoroshi.utils.crypto.Signatures

// the constant time comparison backs apikey secret and bearer checks, so it has to stay a correct
// equality first and foremost
class SignaturesSpec
    extends org.scalatest.wordspec.AnyWordSpec
    with org.scalatest.matchers.must.Matchers
    with OptionValues {

  "constantTimeEquals" should {

    "accept identical values" in {
      Signatures.constantTimeEquals("s3cr3t", "s3cr3t") mustBe true
      Signatures.constantTimeEquals("", "") mustBe true
    }

    "reject different values of the same length" in {
      Signatures.constantTimeEquals("s3cr3t", "s3cr3T") mustBe false
    }

    "reject values sharing a prefix but not a length" in {
      Signatures.constantTimeEquals("s3cr3t", "s3cr3too") mustBe false
      Signatures.constantTimeEquals("s3cr3too", "s3cr3t") mustBe false
      Signatures.constantTimeEquals("", "s3cr3t") mustBe false
      Signatures.constantTimeEquals("s3cr3t", "") mustBe false
    }

    "compare non ascii values on their utf-8 bytes" in {
      Signatures.constantTimeEquals("clé-privée", "clé-privée") mustBe true
      Signatures.constantTimeEquals("clé-privée", "cle-privee") mustBe false
    }
  }
}
