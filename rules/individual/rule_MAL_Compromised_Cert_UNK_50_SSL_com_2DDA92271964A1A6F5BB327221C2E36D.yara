import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_2DDA92271964A1A6F5BB327221C2E36D {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-17"
      version             = "1.0"

      hash                = "ce19b6511fa04c0b6121fbbf208e86a74430657e4266ae806e3f897ff13cea4d"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Keravan Kirja-Info Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2d:da:92:27:19:64:a1:a6:f5:bb:32:72:21:c2:e3:6d"
      cert_thumbprint     = "96D6A605135A4092107EDE41235E5E71C1C6DC83"
      cert_valid_from     = "2025-07-17"
      cert_valid_to       = "2026-07-17"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Kerava"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2d:da:92:27:19:64:a1:a6:f5:bb:32:72:21:c2:e3:6d"
      )
}
