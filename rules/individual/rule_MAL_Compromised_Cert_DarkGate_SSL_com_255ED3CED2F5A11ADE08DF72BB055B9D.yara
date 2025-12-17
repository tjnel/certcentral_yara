import "pe"

rule MAL_Compromised_Cert_DarkGate_SSL_com_255ED3CED2F5A11ADE08DF72BB055B9D {
   meta:
      description         = "Detects DarkGate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-05"
      version             = "1.0"

      hash                = "b79b536569c0060a834e4001289a6700692d67df58e644779fababf0df22fc75"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "AAA CLOTHING LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "25:5e:d3:ce:d2:f5:a1:1a:de:08:df:72:bb:05:5b:9d"
      cert_thumbprint     = "DF4E044C56147E7629B9C7781A5FE88996F91C5D"
      cert_valid_from     = "2023-10-05"
      cert_valid_to       = "2024-10-04"

      country             = "GB"
      state               = "England"
      locality            = "Wellingborough"
      email               = "???"
      rdn_serial_number   = "10260060"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "25:5e:d3:ce:d2:f5:a1:1a:de:08:df:72:bb:05:5b:9d"
      )
}
