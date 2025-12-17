import "pe"

rule MAL_Compromised_Cert_FakeNSFW_SSL_com_1084709258B748EC1FF4713256826408 {
   meta:
      description         = "Detects FakeNSFW with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "b1b89efac3f6f9bbde0abc10ae8b8ff2c966854f40893d5b17cc29c58b4ce8cd"
      malware             = "FakeNSFW"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Lis Elewacje Spółka Z Ograniczoną Odpowiedzialnością"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "10:84:70:92:58:b7:48:ec:1f:f4:71:32:56:82:64:08"
      cert_thumbprint     = "F03E1737D59C16188D889CBCC48193D3A7DD9253"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-07-30"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "10:84:70:92:58:b7:48:ec:1f:f4:71:32:56:82:64:08"
      )
}
