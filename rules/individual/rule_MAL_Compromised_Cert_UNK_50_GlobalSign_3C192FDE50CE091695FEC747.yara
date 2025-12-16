import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_3C192FDE50CE091695FEC747 {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-26"
      version             = "1.0"

      hash                = "ddc4e905066f11ac1703175c5fe3d0a76b337a7083f27107484baa5feb855778"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "BINARYPI TECH INC."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3c:19:2f:de:50:ce:09:16:95:fe:c7:47"
      cert_thumbprint     = "fe6bb6ca2d79762bb663b9aa96277188ce5fa3b3a50ec1ee39a6b5bdd070dc58"
      cert_valid_from     = "2024-12-26"
      cert_valid_to       = "2025-12-27"

      country             = "CA"
      state               = "Ontario"
      locality            = "Mississauga"
      email               = "???"
      rdn_serial_number   = "1138775-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3c:19:2f:de:50:ce:09:16:95:fe:c7:47"
      )
}
