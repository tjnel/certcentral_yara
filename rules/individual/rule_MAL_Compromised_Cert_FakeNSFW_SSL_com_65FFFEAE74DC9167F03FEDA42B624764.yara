import "pe"

rule MAL_Compromised_Cert_FakeNSFW_SSL_com_65FFFEAE74DC9167F03FEDA42B624764 {
   meta:
      description         = "Detects FakeNSFW with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-27"
      version             = "1.0"

      hash                = "459f3e4e77b3b5c3d24a39a8c219442a12f41a2528f15702520ec19c69dea43a"
      malware             = "FakeNSFW"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Future Trade Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "65:ff:fe:ae:74:dc:91:67:f0:3f:ed:a4:2b:62:47:64"
      cert_thumbprint     = "5671CC35C02EF1AAB3D2B1B921B71BEFC551A7F3"
      cert_valid_from     = "2025-06-27"
      cert_valid_to       = "2026-06-27"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "65:ff:fe:ae:74:dc:91:67:f0:3f:ed:a4:2b:62:47:64"
      )
}
