import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D7C432E8D4EDEF515BFB9D1C214FF0F5 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-02"
      version             = "1.0"

      hash                = "fc59281d717018816d0ff8f2aa58e5491df892d3e85c50c8826b8e0ee5904af1"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "LLC \"MILKY PUT\""
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
      cert_thumbprint     = "045050E789C0E3DFC972CC97EFB4A49709A80AF1"
      cert_valid_from     = "2020-10-02"
      cert_valid_to       = "2021-10-02"

      country             = "RU"
      state               = "???"
      locality            = "Sankt-Peterburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
      )
}
