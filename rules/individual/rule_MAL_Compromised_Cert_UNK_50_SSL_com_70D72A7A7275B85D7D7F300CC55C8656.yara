import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_70D72A7A7275B85D7D7F300CC55C8656 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "472e5724498c4ca71d0a10fbccfdf492530a4e2e59511e42343154cbe0fe92d0"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "FROIZINE ANNI E-CO LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "70:d7:2a:7a:72:75:b8:5d:7d:7f:30:0c:c5:5c:86:56"
      cert_thumbprint     = "F4C43F1A7A72F6FD3F925F13EDB66496302E5AC3"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-07-30"

      country             = "GB"
      state               = "Dorset"
      locality            = "Bournemouth"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "70:d7:2a:7a:72:75:b8:5d:7d:7f:30:0c:c5:5c:86:56"
      )
}
