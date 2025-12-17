import "pe"

rule MAL_Compromised_Cert_Vidar_SSL_com_70044DC752FEE75A0835741593072573 {
   meta:
      description         = "Detects Vidar with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "fda2f164f9151d249283e92213f038455a0bb3968a3d6960a58abf08eef03cf2"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "2S-Software AG"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "70:04:4d:c7:52:fe:e7:5a:08:35:74:15:93:07:25:73"
      cert_thumbprint     = "D2637FE9093F76C98DE460DD6D5052C4D55F689C"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2026-07-03"

      country             = "CH"
      state               = "canton of Zürich"
      locality            = "Andelfingen"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "70:04:4d:c7:52:fe:e7:5a:08:35:74:15:93:07:25:73"
      )
}
