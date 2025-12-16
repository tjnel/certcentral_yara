import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_46EBF14BF2B2F88F2EE3372CB0F6AA9E {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-01"
      version             = "1.0"

      hash                = "341b7c4f0a76487e345ed2e79e29c3c1043f5ca77e0a2008928fc8d7bf51cd18"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "NXG Software Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "46:eb:f1:4b:f2:b2:f8:8f:2e:e3:37:2c:b0:f6:aa:9e"
      cert_thumbprint     = "88F53BCA3C84A4184D2C79A7ADEFA552048843D1"
      cert_valid_from     = "2024-07-01"
      cert_valid_to       = "2025-07-01"

      country             = "GB"
      state               = "Kent"
      locality            = "Orpington"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "46:eb:f1:4b:f2:b2:f8:8f:2e:e3:37:2c:b0:f6:aa:9e"
      )
}
