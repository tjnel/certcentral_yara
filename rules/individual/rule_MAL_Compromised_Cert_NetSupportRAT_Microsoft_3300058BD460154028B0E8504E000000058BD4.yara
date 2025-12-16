import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_Microsoft_3300058BD460154028B0E8504E000000058BD4 {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-02"
      version             = "1.0"

      hash                = "c7cefe78fa66d76523beb05969fc5df2eff2db1512249bbcf9fd8fb2220723de"
      malware             = "NetSupportRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RITZ AND JOHNSON BUILDING PARTNERSHIP, LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:8b:d4:60:15:40:28:b0:e8:50:4e:00:00:00:05:8b:d4"
      cert_thumbprint     = "D5B56201BE8C2A43291A1F8381BDBA39F4345F2B"
      cert_valid_from     = "2025-12-02"
      cert_valid_to       = "2025-12-05"

      country             = "US"
      state               = "Florida"
      locality            = "OCALA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:8b:d4:60:15:40:28:b0:e8:50:4e:00:00:00:05:8b:d4"
      )
}
