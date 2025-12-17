import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_627BC57981E18D8EC4DD9D1AA500A8CA {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-03"
      version             = "1.0"

      hash                = "0fe151a3925e90f87ca716372a8eb7b4195dcfa7e64591a350ad6655ca36446d"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Air Code Design inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "62:7b:c5:79:81:e1:8d:8e:c4:dd:9d:1a:a5:00:a8:ca"
      cert_thumbprint     = "152B35C0C7ABC1AEBCB211753BA0D49446D3E34E"
      cert_valid_from     = "2024-07-03"
      cert_valid_to       = "2025-07-03"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Kelowna"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "62:7b:c5:79:81:e1:8d:8e:c4:dd:9d:1a:a5:00:a8:ca"
      )
}
