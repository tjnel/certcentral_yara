import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000533704E59FA6459994230000000053370 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-28"
      version             = "1.0"

      hash                = "4ab1ab98fee5f786837afa7d8aadc0245cbf133e4b3eb74974b564b8d972868b"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "BLUE STONE REALTIES INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:05:33:70:4e:59:fa:64:59:99:42:30:00:00:00:05:33:70"
      cert_thumbprint     = "2FC01A1C41017B346BCE390528BE4CD0A1EB65F3"
      cert_valid_from     = "2025-08-28"
      cert_valid_to       = "2025-08-31"

      country             = "CA"
      state               = "Québec"
      locality            = "Montréal"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:05:33:70:4e:59:fa:64:59:99:42:30:00:00:00:05:33:70"
      )
}
