import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_27CD9AAFD8A9E3C32C365F75DF24C59F {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-13"
      version             = "1.0"

      hash                = "36ddf45c5d3b0bd830107dd4b31742372e31b81db79b757c2357049bf37de9a9"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Destiny Software Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "27:cd:9a:af:d8:a9:e3:c3:2c:36:5f:75:df:24:c5:9f"
      cert_thumbprint     = "9F1A0A1F31FEEE993F5B3ECBB9FE5EE536B85594"
      cert_valid_from     = "2024-08-13"
      cert_valid_to       = "2025-08-13"

      country             = "PL"
      state               = "Lubusz Voivodeship"
      locality            = "Zielona Góra"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "27:cd:9a:af:d8:a9:e3:c3:2c:36:5f:75:df:24:c5:9f"
      )
}
