import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_4743E140C05B33F0449023946BD05ACB {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-11"
      version             = "1.0"

      hash                = "0170f0382c417a0c0b14cce5c023563e60cd75583a0ce5d6393f4d1f55d548e6"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "STROI RENOV SARL"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb"
      cert_thumbprint     = "2E36340548D27E6FD8A5131FDB07405CEBD38C42"
      cert_valid_from     = "2020-12-11"
      cert_valid_to       = "2021-12-11"

      country             = "FR"
      state               = "???"
      locality            = "PLOMBIERES LES DIJON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb"
      )
}
