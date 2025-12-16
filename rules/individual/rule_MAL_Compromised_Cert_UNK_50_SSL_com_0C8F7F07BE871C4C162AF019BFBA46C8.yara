import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_0C8F7F07BE871C4C162AF019BFBA46C8 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "3ff2a50bd7bbadbf474ecea6d6094321ec0dbd0db7446b2c6d2042edb2203b16"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "SRL OXYGEN PLUS REASEARCH AD NETWORK"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "0c:8f:7f:07:be:87:1c:4c:16:2a:f0:19:bf:ba:46:c8"
      cert_thumbprint     = "42AC42F78990BA525E72BB4BB84E0E4DDC34B73B"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-25"

      country             = "MD"
      state               = "???"
      locality            = "Chisinau"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "0c:8f:7f:07:be:87:1c:4c:16:2a:f0:19:bf:ba:46:c8"
      )
}
