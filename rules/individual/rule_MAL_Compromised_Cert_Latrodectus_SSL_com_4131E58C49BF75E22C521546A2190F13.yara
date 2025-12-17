import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_4131E58C49BF75E22C521546A2190F13 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-28"
      version             = "1.0"

      hash                = "d22c96565d2640d993f7280731112287986c24cb1636126da391634ed478ed1e"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Digital Tags Finland Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "41:31:e5:8c:49:bf:75:e2:2c:52:15:46:a2:19:0f:13"
      cert_thumbprint     = "8A72BD6ADD0E597504C52AAEA9B87790FF5FDAF4"
      cert_valid_from     = "2025-04-28"
      cert_valid_to       = "2026-04-28"

      country             = "FI"
      state               = "Pirkanmaa"
      locality            = "Tampere"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "41:31:e5:8c:49:bf:75:e2:2c:52:15:46:a2:19:0f:13"
      )
}
