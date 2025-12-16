import "pe"

rule MAL_Compromised_Cert_FakeWallet_SSL_com_74CC097BCA0EBAE54EC126E526AC20DC {
   meta:
      description         = "Detects FakeWallet with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-18"
      version             = "1.0"

      hash                = "876538da922976743c40a8d49723cda325463c6f1a6baf1c28027a383ff14c6b"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SPOTLESS SQUAD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "74:cc:09:7b:ca:0e:ba:e5:4e:c1:26:e5:26:ac:20:dc"
      cert_thumbprint     = "D96E7380003C5BDE455FC44FEBE5566ED46F0191"
      cert_valid_from     = "2025-09-18"
      cert_valid_to       = "2026-09-18"

      country             = "KE"
      state               = "Rift Valley"
      locality            = "Eldoret"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "74:cc:09:7b:ca:0e:ba:e5:4e:c1:26:e5:26:ac:20:dc"
      )
}
