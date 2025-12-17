import "pe"

rule MAL_Compromised_Cert_RemoteManipulator_Sectigo_00CA4822E6905AA4FCA9E28523F04F14A3 {
   meta:
      description         = "Detects RemoteManipulator with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-02"
      version             = "1.0"

      hash                = "c1fe973ec51d405df053a593909e50a2f6929e95966557e0b5188861ca983c56"
      malware             = "RemoteManipulator"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ELISTREID, OOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3"
      cert_thumbprint     = "35CED9662401F10FA92282E062A8B5588E0C674D"
      cert_valid_from     = "2021-03-02"
      cert_valid_to       = "2022-03-02"

      country             = "RU"
      state               = "???"
      locality            = "Saint-Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3"
      )
}
