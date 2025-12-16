import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_51BB990298810B66ABFC5A8F81723E58 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-12"
      version             = "1.0"

      hash                = "abec391509493b746cf8a057f9ac9304660a723bc2cd2d9e36154df4bed73ab8"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "PRZEDSIĘBIORSTWO USŁUGOWO HANDLOWE MAKER SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "51:bb:99:02:98:81:0b:66:ab:fc:5a:8f:81:72:3e:58"
      cert_thumbprint     = "CE90CF862F0E8A964664B7CD3BA80CBD19D01014"
      cert_valid_from     = "2025-07-12"
      cert_valid_to       = "2026-07-12"

      country             = "PL"
      state               = "śląskie"
      locality            = "Żory"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "51:bb:99:02:98:81:0b:66:ab:fc:5a:8f:81:72:3e:58"
      )
}
