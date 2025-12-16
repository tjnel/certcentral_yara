import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_6386FDF30F59906C2AADCAF1 {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-26"
      version             = "1.0"

      hash                = "d7ba2559c546275420c9ae4a7640af759cee72a10266f9db6f6846a61979f288"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "LLC Grayauto"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "63:86:fd:f3:0f:59:90:6c:2a:ad:ca:f1"
      cert_thumbprint     = "8735CD67B734549F57104C77524CBD8B3E5963ED"
      cert_valid_from     = "2025-03-26"
      cert_valid_to       = "2026-03-27"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "63:86:fd:f3:0f:59:90:6c:2a:ad:ca:f1"
      )
}
