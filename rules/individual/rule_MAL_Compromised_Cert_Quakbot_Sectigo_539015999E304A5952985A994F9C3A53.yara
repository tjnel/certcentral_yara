import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_539015999E304A5952985A994F9C3A53 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-04"
      version             = "1.0"

      hash                = "31b1c3b7706cbd03c97eb962c049dd024c06129648849206530dd960d2fdf115"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Service lab LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53"
      cert_thumbprint     = "AD966944FC007A8E75128744541AB9F995BD0706"
      cert_valid_from     = "2020-09-04"
      cert_valid_to       = "2021-09-04"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53"
      )
}
