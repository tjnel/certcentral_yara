import "pe"

rule MAL_Compromised_Cert_AsyncRAT_SSL_com_46E097EBE44BF0363E5830369D708B81 {
   meta:
      description         = "Detects AsyncRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-07"
      version             = "1.0"

      hash                = "374c270caa42b3ba1a0b31c33a47fe590c38ef8997845d48ae3fb8a575f7d608"
      malware             = "AsyncRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Monni Software Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "46:e0:97:eb:e4:4b:f0:36:3e:58:30:36:9d:70:8b:81"
      cert_thumbprint     = "C0B18FA57D2D12AC58918ED685F67D930A6A785A"
      cert_valid_from     = "2025-02-07"
      cert_valid_to       = "2026-02-07"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "2665076-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "46:e0:97:eb:e4:4b:f0:36:3e:58:30:36:9d:70:8b:81"
      )
}
