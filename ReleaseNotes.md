#	Release Notes - ding_u2.2

**Developer & Maintainer** - [Rishi Tharun](https://linkedin.com/in/rishitharun03) - <<vrishitharunj@gmail.com>><br>
<br>

> Release Date: `TBD`
> 
> NOTE:
> * Only the current version release is pushed to GitHub.
> * Contact the developer for previous version releases.

<br>

Key Points about ding_u2.2
--------------------------
* ding is upgraded to Branch 2 - **ding_u2**
* This is release 1 of Branch 2 - **ding_u2.1**
* ding2 is completely incompatible with ding1
* ding1 is deprecated, and will be left in its incomplete form

<br>

Changes made/Features added in this Release (internal):
-------------------------------------------------------
* The basic network datastructure is modified, to do packet assembling faster, without copying

Changes made/Features added in this Release (code prespective):
---------------------------------------------------------------
* `container()` will now have either _no_ arguments or _two_ arguments
* `container()` with no arguments will create an empty base packet container, on top of which each layer will be added
* `container()` with two arguments are meant for the subsequent layers used in the packet.
* arg1 will be of _string_ type, that specifies the protocol layer/payload
* arg2 will be of _packet_ (base) type, that specifies the base packet on to which the layer is to be added

> This release has all features upto *ding_u1.3*, in addition to the above mentioned features

