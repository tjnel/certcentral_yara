import "pe"

rule MAL_Compromised_Cert_FakeMSTeams_SSL_com_10B773CE74FFA557CA5820731EE44E9E {
   meta:
      description         = "Detects FakeMSTeams with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-14"
      version             = "1.0"

      hash                = "6b1251fb7b4f9458922c94f0abd0584fd891860ec12fee5da428b7b6dc1136f0"
      malware             = "FakeMSTeams"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sichuan Agromax Technology Co., Ltd."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "10:b7:73:ce:74:ff:a5:57:ca:58:20:73:1e:e4:4e:9e"
      cert_thumbprint     = "4B26BDE45CD7225B4B2924F1230F47E46714725F"
      cert_valid_from     = "2025-06-14"
      cert_valid_to       = "2026-06-13"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510100MA6DEAE88D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "10:b7:73:ce:74:ff:a5:57:ca:58:20:73:1e:e4:4e:9e"
      )
}
