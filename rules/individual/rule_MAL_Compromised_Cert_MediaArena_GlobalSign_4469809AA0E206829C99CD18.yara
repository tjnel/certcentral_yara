import "pe"

rule MAL_Compromised_Cert_MediaArena_GlobalSign_4469809AA0E206829C99CD18 {
   meta:
      description         = "Detects MediaArena with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-21"
      version             = "1.0"

      hash                = "0bda8ea6fb5f46f110c18e72bcef514d5cdf5270f310e7286d3d03a263ed8772"
      malware             = "MediaArena"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LIGHTNER TOK LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "44:69:80:9a:a0:e2:06:82:9c:99:cd:18"
      cert_thumbprint     = "B0F054A3A02999D47B5FADE5C33FA9C9FE1B951F"
      cert_valid_from     = "2024-02-21"
      cert_valid_to       = "2025-02-21"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Tel Aviv-Jaffa"
      email               = "contactus@lightnertok.com"
      rdn_serial_number   = "516201944"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "44:69:80:9a:a0:e2:06:82:9c:99:cd:18"
      )
}
