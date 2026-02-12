import "pe"

rule MAL_Compromised_Cert_RomCom_DigiCert_07B749F7C9E5021A1EF5B61AE96A6C46 {
   meta:
      description         = "Detects RomCom with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-29"
      version             = "1.0"

      hash                = "e20f3a7806418c2739ad3d47959857eb0dd2e4960e966f413c6e047d11d003f0"
      malware             = "RomCom"
      malware_type        = "Initial access tool"
      malware_notes       = "Malware was distributed via fake Google Drive."

      signer              = "XRYUS TECHNOLOGIES LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:b7:49:f7:c9:e5:02:1a:1e:f5:b6:1a:e9:6a:6c:46"
      cert_thumbprint     = "12D7C73BC6DA49B8BED75F1FB677A2A024D0757E"
      cert_valid_from     = "2026-01-29"
      cert_valid_to       = "2026-12-04"

      country             = "JP"
      state               = "Tokyo"
      locality            = "Minato-ku"
      email               = "???"
      rdn_serial_number   = "2900-01-095356"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:b7:49:f7:c9:e5:02:1a:1e:f5:b6:1a:e9:6a:6c:46"
      )
}
