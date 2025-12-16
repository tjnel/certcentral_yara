import "pe"

rule MAL_Compromised_Cert_StealC_Microsoft_330005639B7F8EE84875A4851500000005639B {
   meta:
      description         = "Detects StealC with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-22"
      version             = "1.0"

      hash                = "83322f93f2b3489c9414317e11e66927d35475ba77a537c012180f3b55a85e1c"
      malware             = "StealC"
      malware_type        = "Infostealer"
      malware_notes       = "A popular and customizable infostealler that can also function as a loader: https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:63:9b:7f:8e:e8:48:75:a4:85:15:00:00:00:05:63:9b"
      cert_thumbprint     = "35F6DEED2594DF4FAAD2CD664EEEEBC00BC181A6"
      cert_valid_from     = "2025-11-22"
      cert_valid_to       = "2025-11-25"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:63:9b:7f:8e:e8:48:75:a4:85:15:00:00:00:05:63:9b"
      )
}
