# LSVID package

This package is part of the Lightweight SVID (LSVID) proof of concept, developed in HPE/USP SPIFFE/SPIRE Assertions and Tokens project.  
It can be imported and used to allow workloads to retrieve its LSVIDs and perform the essential operations (e.g., encode/decode, extend, and validate).  


# Requirements
To be executed it have two main requirements: (TODO: Add link to each repo)  

- SPIRE fork with a modified version of FetchJWTSVID endpoint, thought which the package retrieves workload LSVID.  
- Modified go-spiffe package to support LSVIDs.  

