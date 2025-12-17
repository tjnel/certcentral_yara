import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_SSL_com_69E19C9125EEC7D62AE596F91F08D559 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-03"
      version             = "1.0"

      hash                = "dd71f68cb9ea204e3f6af6661fe23a8e3dda40fa4bf968d6f0907566eb45128a"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "NEXTGENSOFTWARE COMPANY LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "69:e1:9c:91:25:ee:c7:d6:2a:e5:96:f9:1f:08:d5:59"
      cert_thumbprint     = "F24DEE9816513680373C82FBCC8A351E14B00C7E"
      cert_valid_from     = "2025-04-03"
      cert_valid_to       = "2026-04-03"

      country             = "VN"
      state               = "???"
      locality            = "Ho Chi Minh City"
      email               = "???"
      rdn_serial_number   = "0318797820"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "69:e1:9c:91:25:ee:c7:d6:2a:e5:96:f9:1f:08:d5:59"
      )
}
