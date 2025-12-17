import "pe"

rule MAL_Compromised_Cert_CleanupLoader_SSL_com_2099128026318AD09C5A2411EF82F956 {
   meta:
      description         = "Detects CleanupLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-04"
      version             = "1.0"

      hash                = "7c0469e049eb1eee34dc7053d5241bbceb6e0773b43a0be813a875cebbe8857e"
      malware             = "CleanupLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanxi Yanghua HOME Furnishings Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "20:99:12:80:26:31:8a:d0:9c:5a:24:11:ef:82:f9:56"
      cert_thumbprint     = "31887A88F6A37A4620143AE13035D26E6AA4FAEB"
      cert_valid_from     = "2024-04-04"
      cert_valid_to       = "2025-04-04"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140100583325252X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "20:99:12:80:26:31:8a:d0:9c:5a:24:11:ef:82:f9:56"
      )
}
