import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_71E98ECE107000F15A341F2AB90A7890 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-26"
      version             = "1.0"

      hash                = "92d903c00e4c59fc3b50b0ba744cb6720b7d9ac81d3c05390a81b70f1ee24ce3"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Viridian Toys Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "71:e9:8e:ce:10:70:00:f1:5a:34:1f:2a:b9:0a:78:90"
      cert_thumbprint     = "DCDFB2FFE103DB97E72916F3ABF0ACA4D95FB5C6"
      cert_valid_from     = "2025-09-26"
      cert_valid_to       = "2026-09-26"

      country             = "GB"
      state               = "Norfolk"
      locality            = "Wisbech"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "71:e9:8e:ce:10:70:00:f1:5a:34:1f:2a:b9:0a:78:90"
      )
}
