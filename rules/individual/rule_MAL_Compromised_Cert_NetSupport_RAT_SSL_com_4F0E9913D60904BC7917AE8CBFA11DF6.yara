import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_4F0E9913D60904BC7917AE8CBFA11DF6 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-08"
      version             = "1.0"

      hash                = "8f700d6ac2bc4e939e959b14b42c637a516c78d16fdbd3605c83872254a1065e"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Affable Software, s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4f:0e:99:13:d6:09:04:bc:79:17:ae:8c:bf:a1:1d:f6"
      cert_thumbprint     = "4D9276AA8BA55CCDE5ABD449D6AE4CE025EB84D7"
      cert_valid_from     = "2024-08-08"
      cert_valid_to       = "2025-08-07"

      country             = "CZ"
      state               = "Pardubice"
      locality            = "Zelené Předměstí"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4f:0e:99:13:d6:09:04:bc:79:17:ae:8c:bf:a1:1d:f6"
      )
}
