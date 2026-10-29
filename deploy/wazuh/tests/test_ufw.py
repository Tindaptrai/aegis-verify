"""Portable UFW admission tests; pinned public package data is never executed."""
import base64
import copy
from dataclasses import replace
import hashlib
import importlib
import json
import os
import stat
import unittest
import zlib

# Official Ubuntu ufw_0.36.2-6_all.deb, SHA256
# 096eb403ecaf6740d160bb306970f025222ef71324319cc1cb78d06dfa462ef1.
# https://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.36.2-6_all.deb
# Selected public files, compressed as data; no package install, source or hook execution.
# Vendor scripts retain their Canonical copyright and GPL-3.0-or-later notices.
_VENDOR = (
    'c-rk<TbH8BlKv~R&g;yX4O;GQX07uelpv^7fpU>Ifht5m-R-S#*8KO0$V?CvFIBty%$c?JL#=KV@)8-BFCsD{|NC#h?KVGtOJo1H'
    '-TMLm{vI#m?ce_E-~OiNz5O&xcf+>6lH$=o%|+f@2HTm_S%=T7Xr|bkK(TYRuP=fuJ%p0T`MDT-W04P9cA_d;NA25Ln2YPMucy8;'
    '9jJ%ZLhb4Mpr7V5CtQV6Hy=HBpN13lFq&AA(UNz5tFxZA<c-?<;5_Mxz9V%bRW?^McN7JEZSS?Uxjz=yK`v%NW~VTQy|*;mQ&&r0'
    'VzJ}5tq9uKseLW=l=K+(we@sqb1=3wjC1a1#@=tMk?#n}%<(!fzX<!7xkeN^oy2q1C{*Uqu9*fIe^eDAga5DK{r)7iBC}=hJQv0w'
    'iALyXo0&6;CQ7>SoX!!RX~A#DnIr7f=h3EUdrHP`$3Bb)XvgS7+EmCK<kK9~p0~$wOkH#Bx1M&C{y+msv}W+W+81-b73Ncii;yO@'
    'IXXr(bDrq<mH9qUEd2i*=8bc2&zz49^bK>fkDlZ4zH}(sjzgHg&8613C)l<mijy>f&+^zx<QH2`zN!6i4Q=i5InVV{KNh(ev_EtB'
    '1I#P+pnVuWjH|=Fjm5nev9;^*vX$tnVRbCS(zHo0wH)|8h(%>=n=huVPhifkRxFCDEQ(fYY6fqQ3|oyX*&bUxVPcM-fCuyx=!Jb2'
    'V}4{kGPc$^{2$iVoC6JxLl|4JHjX3kz(Xs)ZEs)>t0~M4d1u<P*I|Zh)dPMK4rESj&L-Ef)n1tTnGN$jL>66J;O`IMUwap{$}!G;'
    'Mc8>c(B3syxaM^}hI#eUOjSDjP&z~)JE{8ou?qX<;U)gQ58GjTn1#D=+}Q_Nu=k63xugASjPkLD{~OWJu?9FFGfAft%lf_Srv>Zf'
    'd?bDxa%9~VpaaM)@W~*^gng)(>tMkRX3jKn@@}j>_hR*#i`1CgmcPep<c_<U7K^?r@jF#glM#M5*$_VSqZOfJr9Egz-K%kTp(;R&'
    'wvDvsf=ph+_>mSzUy+ZqE_<&vUwca<8b#}DW~`C#=fKnXtFc~tq)+H?tVXZnZaf_G<?m`NhN?8pRCxpQ2Rg<E`R*mhHL^i&2>nm('
    'jd9%HV^so~0UCxVYkd>eF9n|IEP)3$Qy29ec@N|?%}_^4nYWfQ`zZk0feiHw+Z0{S)GVB*V$MTFPG+teOUUm%GX=dl_hZ2ZdEAA4'
    'Tnl|WrE&*)$B2Tqm{K|A4?we)=kTe&GzP;M=-=OhYzrKY_kAp+p)!K?^V-8U>e9{v^kb$*mvjl*<~&#$u_|+s78h%&(zRU5{LHbr'
    'D!tU$lqZQSO?q|@)=5w$ZRh8gYwEdk&>P(Yp+VU%=tSuIt&Q_BVeXnRYyscL0@?^VUMJmwKHYjigJ~P}Sm$`THr?Hq+KJYw4>pCZ'
    '6Uga&595Dk^1DMCdtkdfsr&i1rTKiC!8#K@P2!@DHznoN=ib1}l7W=zbC7T3w-1=p+K<*p-~r%`WI*(tMCBXwz!7ZJ7UYkcx#9+7'
    'APtrp>OG>b{VY7P_H&S7VZ`JC=D~rj;9ecHx#2rqTQgGoAKy_gh0iEo-;1$vo~v_(To&)bnxeci+El+6p^b0_I*{r(;6oyl<L)<A'
    'G52g;s6BLU@DYxM@{ws<sccJ>58oWSX`N4hioKXA-|;<^xs;4Y31R--Xz2DLHPwI2;QwsSKqJsT$g_&R_wn=6POEL=dYsy?%$Lkb'
    'rN6<v{LEtix1Z3?L;px~M#Jv6mjkY$a2ObL4Uj+Fw$AzOZuH(i6mn3ZJ9!6ei?;B_{MC0sU$JMz@9za4!T4TtHn!)@H)*M*Y`)(;'
    ';Js<f0^MtG{Fa>5+tdI@33K4_8*S+v=sP~h8C?*A@dENE7lJ*wGM5FlL4cPsw38j6JG8CHAVcCDa7h}(?7P0s2Ys;Jps%%d(N_Sv'
    'ZOsQLcYs9#<zxOv?6kdwHnI@xP1#R<JgdPNY(Y-23F0}>hc*YYmj+D#Fdp2#;do`u27NVgc~P``5#UoBX`2o+BFCuvz7b62JXLt&'
    'f%p2wJg(4H0o_Mst<Zl@_`8+bBfu{2R!_FZl2E79H5rJ_v2A_G7B3iJN7P}9(&zJIVf+U;ZYJ@7F%IjJ#<GpL2i8H((XRRZWC!aD'
    '>*;Mmuy24J7(UcMo<BI$gCJiku!FlG2mSzT4>&1>F<`rqp9#C6L!X_Mv>gE^ngf;sok{rw<VjD%K5H9z1hES80j#fRaJp>C2Ae}l'
    'ZMGXV(Bq5;AEx8QdsW(8;d>GA2D5Y72ly@Xcd*%OzmIz6nyma2cz~_b(2+O3^avlU{wVZ>=Kzicoo&1N+-m{$kOa`PY6U~^OpdqI'
    'X7xXa?t1TE*Fo=!2iQ|jhc4<g@jIneL@>>J!LM!Z!d8|#DYK7LXEczafBfTb|M73lPUqj>ci>*etL5gd`zi4mxJL_66JQcXzXK_F'
    'KhrsMxqxNQ+)uu$$^ZuF07Fx7b%<*fk@gA~wm<sIMg7Y~{mVuDl`d*ZOt7HF!V%^BB^F}fh2KFn9fQ+%piWdG|7x@vpgK~)tjvgu'
    'XMQt5)f%?Y8`}u!ZEl(i3Gm4rVK!B9>b2)i&_4q>nN0!KZh$wxpP8i*zJC?QQa5c>s=Jdb(yggrqb2aZVxaj%(+heCAQQ}EpvW=6'
    '4-QT9pn#}SgX%;TpHb*4r8Nj6+?Zc1rS`<MHENR3Rp@U|F6)xp1Ai?Toxqi$rp9d*=Dl+qNJ;c|DBM3S2i}DK)Dk|!{En|<Z5{MY'
    'aFsp)Ca5R+Dd|C97T<Tb6G_x2sR**#-THC&--j(T4P#*!qKrSQ|E?{14Ui4#U@w9ry4SS7db<@9Sh%UkBls-nPv{3^Xr4~nqZ0mC'
    '*N3z@?rzPPnpWbHfh$j37uFvAGhrN7G_)fI1sE-s>1hn~kMswSzyLXU0exVpJ^9(-Y{Qlw?V}q_c-#8wyJjMcQ4g9@3AGx>T!SGw'
    'y2?Q`L))mJJ4kdrn00`RL?;8EDpqw}0Q!`31)c_Im4zFm<>XWA+pVlwLgadEbqw1!Dl`CHn}(v57@%J@(9NLlfwpEY8WUc(PM<H`'
    ')`oSdjn#xX%*OX<d&w_gn@ZXs%{3UiVd>ANEn37K1_&3xoIo}@p!?!W*SF$^N@wsB^{=rip*84?HrPfOv$<jR1iq62wow_VK+%dE'
    'k}>Y4sB5hQ35mVNpc~yO;3R-@fMs6e=|_`JtFA@42C_H?J@RVXrZ!1}2yL7#pFTr7iGMh!*|qUZ3BB&f5yLnlHw7DsZpzR#=)6(3'
    'By;_+Y}8!-lb$F;8f>jt=!>jZv-^l{4Zz#%DH@foLNa)VwJO{nw*|JuLH;t(o&8q07QP}cNyxF#@qM!cSf{Q_CtO^a@0p81!>kxq'
    '(Hp|8^)`*XKL4WaZi~wCi9RHRRg4jE$23QsN$_<N_S1tm<^lGHOSDfz$4vcYLc$Lk?Q08IVd=FnJch2-$3Dz!?_&53pIIR0sJ;hw'
    '23(_R+u&|uNQ&TelY4VTa4`V$xhlM$ZZR}Bb@YV?^ttg&t&gC!T?ZiVehzpK!+q@peTGAL{#<7N0d|FJ9D~E$G3R6NwL%O*HMTKz'
    'JPyav^c$NixRD|cGEk*Y3|IwllGWU15t_KuchfvkhQpSed-eWu&sl>lG_L*5T-NHk!1$KoJjj~od!-%pyJ|GM{oIv4%K6{>{cb;)'
    'ZdlB65`II>pVWB>!~Xh@A>it;f3ZfzyG`qNoVC&eyuTm1MTmn3f5W`NV~u?@(Ea9fjeT6oRAU>A=8eCV{8)yFYqC&;RT}!JVrQwY'
    'w`|LET`qkA-|5}#*^+GqEQCySezPt+3*l1RZ4x~S|1LmR1D?3F7tB5<UiLBf@@_Jvp))Qx4;6z?<r%9h7@^V+;FcPWAz^nj51m`K'
    'do4)O8vKxt6m-XXVH>Jgy1`yhyIA6V7J}o2h2P>4Yb0RzW~yX-6!r@+TaWf(G5=o&dO`n+oP+PT04zsBSE2Gf0{%-vM+YBU2aIo`'
    '?4n<d>;J=Z>;uDlhagM0ARiqS=i!b{DU8<l!Y?QIBfyk}Q||}ouC+0RV9&$Mx)D|s{|GTn(Kq)blwZ<v6itb&iJK{g9AjdO=3u|q'
    'Ugo7RhaL0}zPr5ezz?;RImT4Bo+D$MFfPPIq&@Jf>@8rA&Y((%R=V-KCGAL>kHk*E|DU0KBIE6(Z+!#CA?(94+)ZLdh+|O45Sbg+'
    'd=2W4Ua^b72c1q`j!yat!)A!PYwv=Oh|iF?QlqUa+iucH7rM7mmM`17q8tC54ZdOfZt8yaUb8NJ)UG!?*GvnNX4-<BYy$;Dq<W`1'
    't_y6-VgulJ+n^cV!C%pAS?HOTW}Eq^Q(wey(-dzrbprSoP~P)XHj1w4CVoovQnMbqh(DbBuF!roT0HGN#cmB-9li*MhkcE&>BCc+'
    'Bk^0ER9bQaX<4Rg@(>i9+TSo;1vcQBi`8>n-Lqc|OB<P%QP=m>-y*ibv^t`Ze8?tC89J6dxkfi^x8@I66jK)bSMb0!UkBqmx9yCk'
    '%v>!6{D7hMxldA}W{0L>G>lblNE~w9U7m-<wFcjXq_13Ur#^QZZ3Uw<#uc}~Q#)8E&63Uci6!(%O5jlUVJ>-y-+Lsss-ex=Uf~J4'
    'eo-U;>ITr?<m`7NwY7;1zFazb)Hc(UiY&yTlWs6Y9vsg2r=ib3mF6khk$R7`!T7X$HRizN@V1{$=ZZ085@$pG@os<YwERy0jAyi*'
    '#_=%D4fcnd6@F^0HpD=Zb3SQ|gVlV*+PaLQu`RZAm^<-PyNzoOJT`5e`MN|0P?=2)doiUvkfySAn+Isj;n}OnWD&plOw8fa@jmG;'
    'mMgbUpx^!0LY&G6eoEwJ<2hVJ(&uyw(mLn^O{6)&^FeL9N4G&I-s<;P(1fJqjc_rIg0_8NTaOA%f_V&*3z@ne<_gGnM4wPh_rn7n'
    '<T-~8Vxz0=D<<%-%=>_SOj&!iXx=F*?Y%;D;vVoA=sV#+aN41n=0(aFur0%T-Bx2v>`IJ{V9TWma<2a2WvE;1+*O`px4Vj8k|L&R'
    'jwgIKa*o~KM>4EytOZi6{$7cF_N+uOfaeb{3o$&sFW9z>G3e&shgPq$RtfOPcldWz#`dbum9a622ORqW_JjYUj7iBKJ2gEF)I@)s'
    'SiD9)lkF{4Ugj}P&Y=(c8Tx!aZgpRuS-3?B#^jGhV$aAHI2bGP+@O#6NIYETD6Y#!qr8-{rtbYXePO#UV~PZ`flSAZwt?z6#5+`n'
    'Wi{P#LzmG%f=wqJ#@O!YXZmL(wld*0+2v_Y26fHZHh{vXPTtyxOKoAe)c9%)t}-{#OikHJ1!`MR2cB<Np>dZ-+OjRq9#_X@+d8&Q'
    '?Nys#rlxi-*EcV=Pf*{l-0C6C*EGLqcj#6sof|aj!xFoW81DW?=<ISgV_cudaaZ*Z^En=g^IyZz#g--9)&l-A)rZ%7;bs{DtOj%A'
    'fFAK6^KffP8l+55#G{6G^ir=;zh+B#|GgTgx$p(M+Y6nyyifDeFOs+mo%%rEC*ScC@0aU57X8ul>fqXp7K=6U6HDGa#hprj@DuNR'
    'W^6@#?QvSNIOr$nSM>3fab3pCzw~Yq`}@TFzP8q7y!qj^2LEf8*^5y6#9E);`OMhP;=1=~0Y374+S+_(tuN!w7w>4ryIW&?%8$=j'
    '4yJ*hFL<CCyR4$ya%Vo+Z;}7_R9{#5^}+Yg_~yZ}mT~-gUso{OACK6gVy!>l29vP@2gbap_6qEIi_Twt@9Sf}$W1)j_j%r=crUHK'
    'f6Cq8;>jlcQXT&Z*WZ+lFT7jOuZZ{6cnz_gYuH+^ajkFY#)tcF&|QzeThRY}?Ar5$<MpwPpVjD{#SXErplu?(3ATD9|9+0y%Q(Gb'
    'Cb;K}j$JI`tAne)O3#$dM7Afg`A+5D1bi%v#+L3e|7C1iYuVt9`##J~90fdgmA?y{32P~9@;I@duli{;W{U6Pme?HkeE9K0_^}?}'
    'JIjTcJzIgvk8D}My%YaObU4|6;3?MMui>3X_@U%+SuiHthi32zi$Ae7lJ5I$w_*k;N7wAjDPR2SX>nbSs2tN{XDpBW7!Offcuu#Z'
    '*cbED>2`sc0`P&Rc(ldgaL?%u+9GoSoU@&_O>(pY{H_<%4z9*g9_WMj`d{zE-~@eQrR1{;YejR!mDmd&mwIT=)>%yZ^Riv+$NTBB'
    'eThwZ%;_!y+=~bPq~Gf7*fV$xX%W(``l;IM$aYS6pN*|%|8Cp+|DS79+H{u}Unjlv*<r^f%l&(|@(;9K%#-gzWg4mRI>Y=n$o~U$'
    'JLMFIZWrWIKfwI9BnO^#7~gldL(tK9`~vg(lf-r#<BB(UpsLgUwbuvZ&K=w{M)MU#Jf&qLzb0fKf)t+bKU<dj2o8<0rg@p~v<~OG'
    '<zg?}S7S^!W7KDU<HcTp`+j3(obm?VZ#VdjzuY#FeWyjdi{=uJfFFQY@n}$jNB+q1OtQa(<;}JHdJGJ0zdF7i3%r%r|7Wbz&HnGk'
    'Ae#0NJRWDcy@&7e{RX?)v=^<kp|iM~2K)_dcx$f&>L1BIezNaM%%lE(O{Yj^&$K+zwmvM}BZfZeNiTPA+tk{-g`ZjZ{nzQMbs%qA'
    'uG^5uDUZ#rcEJ+k(4$>>7A(V<yLn`?lmVSLew+C0O)>XEj(%^FO_lDYsl*$oZ}Zr*j4!(l^JB-0n|$hqwwuOH@`j+pIl3py!aNVr'
    'VW`huqFa69nIhDE`rPkcv*onhz<J)~0h?X54QGB`_j_}j-9MX4%R{HLBe-4)F4}L}Gg8e%JaQhP$;bLsK0MJYB|+G^q}-H1u3oLg'
    'ey6#t(ei5lf5x^b>A^XAVX-H@YP(o$<&PpSHH?e1gz(H2-fHx(Sgz_e-_>KBH)ZH7-v7w6r5?Y>)0StEvs#qq_k9Gm7p76iJs&U+'
    'TF)ouYIJ9x!QDL*pwo6fmea_)ORXm>cJGv9{1@iuGdcv<_W3*#+iB8yWG~}wTzXn(mWM6Z<erbN-p0qI?_0R*l2^!CyfggrXZO%O'
    '=(}Fvrn7$U;w-k;^zj_b#Xi%A`}jg`_4*$Cue|$}G1EP`pM3tbulE=F88>iM{S2Zj`g+P2`==_ln#$QA?tooI+*R%Yua}!pygfOK'
    'gll)W+Sd(ybrlO;<g>o^?p6H7#>Psu<hS!9_xrwjcIk?qZm@Hwev5qUSKj@^m@8*_z)rmxcWHFtD?d(`N7wKyH+O&CE^_>L`>4y~'
    'T^bj<V&?Ez17kjI!RNm5Rh&@UEA+E*Z{6Nqv%Qbu$%l1_BJ5{vst>R{7uq8~|C#%BE`8{8U#ux-SUV3PKhjn$S98-A-tf;$J#v=s'
    'Xl$>1=I7_eZtShP<R@A)!6avjSP8eKCbN15zsN5^--7w)WgUrA`J(R1Q^+|ev^mAupwoWIKHEdr*Y~tOhR9v+U&I)KmV1u;1J4?T'
    '{Sek=!^$Ok@NTd_)eWF~T)n=X)AnfzRoq_={?N#JUPYrx!s(0Xpi51;HnMl(9ph1mk#FUVZtSJJ5uc%PbMO-frlmg;H)nh=9Q@Wn'
    'fDz&R9*yNQ`_nj|%h*u#Ps+h6#omW6&FPf$Zv&5EeU3YM(Z|-QAr|)Od6jz#7`-*RU;1&MXaf9)rS96^ILt}x*flxI$JgWw&;9A#'
    '5ab*%<$j3g$6K@}iH0$^Mp;U?WIwzj<JrKKN6L7D{Pn|>ocl*Vuy5~(+_uR1MI2AdWBZ)(Tn3(P^fEagUe4`So@Y^<ZN#&G<$2EY'
    'ed-eEgNr@rr#&&6JG$^+PJ4AO-#v?+R^<uLkk!@<ey_>QSL31edK6Vz>P16$#m<xfukq=`;LTC36f3QtbMgCCJ<-=YK?}wP_6hAu'
    'fPdg~j4>z0>z>8w)<n8;ruR&z-z*nMG3t)i5W9EA1>=Ty%e(!P&l}as#IX{Y#**&CHc4$OQopG<BXDn@%9Zn4xR;)tS9<JRqeN;r'
    '?OEL;T*FvH9Vy*9AJ=O>OMM>qVdo4jlB;0!rssFE^4#7t-D9Rob6Wb<>98|0$wiqz#vib@{O?6s)T?!#T7Vg2ft?fN)AISKUI(O7'
    '?z39|qgJ9<ozRlX><nSOOmFqfq|~dO(Yo=BcRgNMo^709jt0-A`E7cZ1J@kZpp9pcUnmxg1{AlXenw)l$yrURQ~i_fMg5Qx`;})1'
    'e!`hQmNR^)Y$ujjy>Z_5PQHio7GP%7nF8q7<()nw6913_S{4#(<dJ%FQGq?<#?rJ^Im<;2_@d3~EMbYp+L?K@Cqt<?E3aW5Huo>i'
    '*z)2ek^81CNVb)Zunv;-z!~K0B`&Yw=ATgNlKefQM}@;(n^Zq5S;|*I`v=dkUexnxI=6Ijj<;HCjGkE%@SM?kZ5?`Exl(fnbKV8E'
    'C%$+69QJ7Ol#QCkTGm-pi!)NuBei@;o}Hd6re`XPI&Sqk9gXLyDrd|9FHnA}^?B2VvpPhJ>8&-psE+~TBxAX^_C*ZaD(lJJu5;F0'
    'o2@(t_=R^*`0akpulo7xKaEMQo`1e99sE^&*rcm|R;?_`A553U-9x3W0QkfoKm()EZl2c(D0Ew;^!RxR`&%~gmM$w|B@bZ3$L$jG'
    ');+vaFVW3(;E7h%65T%$-`;<h+Bt%`uj|WSan}EVwPCpT3-m>-UZ0a18^5U!&*MzqZu!#>mHF1Vv-SRHmPva<YPDX$cl7Lf7jR~G'
    'MQe@PJCa9njCIvc+>pa+IreWSY*(%OS+RBHKCU9qR>nS??HfIV`K_r&s+py*79lCojr(QD_%WuIbx7&|W}D1nw|#DKt~0=AboBVD'
    'zNpqgxT!17&+;S2*W<6xw}>@{PUi>igYc>E$a#|$=Du1w_<ytf5Mh1f;tcl8)iDm*kQ;BHokMC_V~+TUXL7*@V)ZCYuwQe{!deF>'
    'zF_?j++W7+o6dQkXkHzMC{+BaL9Mn;a`G=!x_9GjEvx<n*34SfOM-9m&Gsz|*}qsF{69BuKlX9(hGoGW-Ujh8Ln#6H*wS+>i-BdV'
    'Uu~FLOV|bqmNu42=?(8ho`I<di;&#1f?I6Uy}!WnT2CZxJa~@Q*d8r~VD>y0T_F?x^ffHM;Ah_l22=5`P8q)41|Uj9XfMdZH0-Wj'
    'EGZov`5jEJ4bT1<x+1DP6!RsPKV~Hnx88EJLsjIpY)(q3T6krppN5WiJhizRIJ^#G=wZ3$P)aGpLTEv5_35t1p2H)I5(%76$juf4'
    'vb~fL_&6ad@0kPlM$fO@ep0H_z_nq%#=u0l$rBSMu(HfoD#(*(22#4!e7to6mfSTc9X!XB-X=V~`J_n4pXNoE{B0Zj7QVgDcIg(^'
    'nU;O;((=TuvNQ$h7t4!dDQt^|>i23Np&GeaU>@|v%^OKSeH7mvLsvXtiRGe%2D-Sa!lzSmTY<3i`$<tY<-EMbLRI7i(EAV)SNMsQ'
    '-VWFFCIlP9EYL@Hi6za6IE{mdlxm}DB+^<;%;0;Lny!chm@+ImPQ#%KQhK+A=>wdTIiI!2HmHmo*@@OfUA?+6*TV`+;7^c`Xq%_f'
    '9mO_^Vhbv1t1OdxV5L1^?BE_0Vf$e$8d$Oo(`2Y}X^B}GRZoU=e#1GFtu37;{S8Gq-G}3%JUhP+NZGga2S7OJ6Xa}ZkZr+J$7Jp+'
    'JnyPeu_Y2@?CNo_N~rnjJWpl38gG`^u++&0Z@4OtdPz@_rF^7Q7t7#*x~r6$C#B!%oY*>8MVg0{=O?A(BysDvVJ@IoW-S}}tUV>F'
    '70cMk$!uvKp)GhGZ^C2S)}nPKEYDnyQ#fC!9M!4vbUi$-oVJ17URP40z6kMy+t<9V*bhR-U$Cx&o5w6BTujG#Yp(L4(A(rnf_v**'
    't}U7SWXz>Tg`WpB9c+?v)>wKN(|asr$mUz6qqv>ANi@anhjgnun5Go31_0Zl|A2NUo@0Sb^K(`rcUj6X@Megq<bI6?q9u#S(*Uc}'
    '*GXDg_f#K_?Jm0|49hK+yv<7f!Mw8%vd*DHZ)us~)?tOfg(7Xe!z%`8Nk%poDMXiSNqKTk%P>-%8TpP3x+pA4d(*OA62Gpr2Wu<r'
    'VV*A7DFOpt;(FR<=F)PKS{rq4P{>6LI&Dt%We0R9PeO@Bf1Xqc&q_=;AJ$E!$B2DpSA1ybk`q0Q*Cll6^#@?@Q0`cG(jt5ed`QYN'
    'R!hU3-dopF53jXb)QVICy-AI(h5dxbXxNdQl->mP6w#wKThb3+!%?v>B#i_#tCw!e@y0k>@*h+BAhTE=xr5uoaUNi+4<XncS^@`f'
    '1g3SF-K5uOlsD;Y{gz47%AjLBauo-)SyKX$!3M#1j5qNLho!*@FB6mr<hfW>P3yxjfy5fQeni*;k09P*TU)$*3Roy?3Hc1xla8n4'
    '<sDvs;^S>)2pvH#Q6Jz{B{&C^6L_A-EtUv5VJsX#UwD^om57BQDMy;6OL`><)fKQVIXp|sQ30GJr93UbYaThK#&40{C5?~72JF04'
    's2pM2z5_okh7$RH2lOJJfmeG5H;M*56KyOWOMb>{J_?;>0Omm`jJHe`n1Jw9=Dk;sM!94T+8T8IJGoM(2cLVIHsMED3Tf^;+8oP@'
    '7HyX$xw?e^Gg8vEIL^fjhoEmBs$&I=!UfN(2y}ymIy=nB&8Y;Qd!R?F7-7hDM7z1&EbOCw!|yxuP$r*$N4x_14bz*7EqCvYjRUM$'
    '8yl=08JpenaBL^+B+Wq&Xe}(48nn{H8z+tH5&&<Y8$<rB(m6>D(1-ejGmCOWaqR}6&3yLbjobm`zrC-1y#42myJzb`0K9(|v;Yl^'
    '+EfFK56Gn(U%9;er$LJY3fEv&ZGzNMN&p?P%TO)~3vqZqByK#M)R0nHOqog;YFI=Wr^|#Y4y~RdG7PhHPM$N^r88$mu5hCgNn|Ny'
    'f#9NGFVPg9BLm6=Z(v-#4C(30rA56Xd^g9tyND)|#8Idi_b=*MYIuRo(QkPi*$@OP%TNQ-E(c@}8o`8qU|gt;u?QWY-(d^22oKJ1'
    'n!OeC!^=!aA|AP&SRhQMZ$XQG=8~ESr3E+;tW5Vf>=tdyICdTj^ny1;3gW%7ixNyahe<gHkPJX*SR|PsjOxWYY%?j|!?^?r*%GH!'
    'sm>AksVuCw^4nsGEJ)#7W)0a!)hu)lrwf(P$(BRS?#*AZ=m}Uq4?c@ls)>`-^j_G7J0z*7*e$QT6e%U1EG-}@=P<4vS`NQ8E!Iv4'
    '?fyLO$uD+Kmd4hHX3Ggd_-2w?U<oE*jR1|QkueqxKx7sm5|Bc9tO6RfQt{Q|EJTY$F0jvH%#W-GwHQ3v2wahm%0*ZNQI^&a<OQ`8'
    '@Q$9&To2cZSlfWkiO#tfzSv{25866~`2xzLYdg)w5%4c)UA-J5XvsY(%1n!Ea%X&u^TH$>CWALb_Qu`sv%ZO1Za-{??J(~w{iOxJ'
    'YfIu4lX(GhKhle=$c8Y9Po-$RAf5wD;^N(R%v(O)wMP;k=>j!3qDIe^c|<<N!H<{YW<Z0fr@KLG=l~D5fai_Hy6bmQl7QT)A4NEj'
    '$OX{m?)`s_&tBdUr{%_nmec!EORItW9$mRh?)-kp^E>3K_tuf`a1Odqw1>3tuz=-Z)no-`@7uQ@w~Rn7YY3(vqkbgI6|z%#VAjY&'
    '&<Ix&Rl*!QdNWsdi4c_;hYSVYb4fVo1nVz$Z&aaC&4nzhRe{pn`}D#~a`ED{O>RdzQe{G-Y~WhhJEpuVw}bs<0RA!ne;I(k48Z>v'
    '15n?A_SU9ZtoQyS7lV@Vrr;(lh#T-f{|octcpv'
)
VENDOR = {p: base64.b64decode(v) for p, v in json.loads(
    zlib.decompress(base64.b85decode(_VENDOR))).items()}


def snapshot(module, path, body, mode=0o644, **changes):
    fields = dict(st_mode=stat.S_IFREG | mode, st_ino=11, st_dev=22, st_nlink=1,
                  st_uid=0, st_gid=0, st_size=len(body), st_atime=1, st_mtime=2, st_ctime=3)
    fields.update(changes)
    info = os.stat_result(tuple(fields[k] for k in (
        "st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size",
        "st_atime", "st_mtime", "st_ctime")))
    return module.RootFile(path, body, info)


class FakeReader:
    def __init__(self, module):
        self.module = module
        self.files = {p: snapshot(module, p, b, 0o755 if p.endswith("ufw-init") else 0o644)
                      for p, b in VENDOR.items() if not p.startswith("/usr/share/")}
        for name in ("before.init", "after.init"):
            p = "/etc/ufw/" + name
            self.files[p] = snapshot(module, p, VENDOR["/usr/share/ufw/" + name], 0o640)
        self.files["/etc/ufw/ufw.conf"] = snapshot(module, "/etc/ufw/ufw.conf", b"ENABLED=no\nLOGLEVEL=low\n")
        sums = b"".join(hashlib.md5(self.files[p].body).hexdigest().encode() + b"  " + p[1:].encode() + b"\n"
                        for p in ("/usr/lib/ufw/ufw-init", "/usr/lib/ufw/ufw-init-functions", "/usr/lib/systemd/system/ufw.service"))
        self.files["/var/lib/dpkg/info/ufw.md5sums"] = snapshot(module, "/var/lib/dpkg/info/ufw.md5sums", sums)
        self.package = b"installed\n0.36.2-6\n /etc/default/ufw " + hashlib.md5(self.files["/etc/default/ufw"].body).hexdigest().encode() + b"\n"
        self.props = {"LoadState": "loaded", "ActiveState": "active", "SubState": "exited",
                      "UnitFileState": "enabled", "NeedDaemonReload": "no", "Transient": "no",
                      "Type": "oneshot", "RemainAfterExit": "yes", "User": "", "Group": "",
                      "FragmentPath": "/usr/lib/systemd/system/ufw.service", "DropInPaths": "",
                      "RootDirectory": "", "RootImage": "", "PAMName": ""}
        self.bus = {}
        for key in ("ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStopPost", "ExecReload"):
            self.bus[key] = {"type": "a(sasbttttuii)", "data": []}
        for key, args in (("ExecStartEx", ["start", "quiet"]), ("ExecStopEx", ["stop"])):
            self.bus[key] = {"type": "a(sasasttttuii)", "data": [["/usr/lib/ufw/ufw-init", ["/usr/lib/ufw/ufw-init", *args], [], 0, 0, 0, 0, 0, 0, 0]]}
        for key in ("Environment", "PassEnvironment", "UnsetEnvironment"):
            self.bus[key] = {"type": "as", "data": []}
        self.bus["EnvironmentFiles"] = {"type": "a(sb)", "data": []}
        self.bus["Job"] = {"type": "(uo)", "data": [0, "/"]}
        self.backends = {name: {"file": snapshot(module, "/usr/sbin/xtables-nft-multi", b"synthetic trusted executable", 0o755),
                                "version": (name + " v1.8.10 (nf_tables)\n").encode()}
                         for name in ("iptables", "ip6tables")}

    def root_file(self, path, limit):
        return self.files[path]

    def properties(self, unit, keys):
        if unit != "ufw.service":
            raise AssertionError("unbounded unit query")
        return {key: self.props[key] for key in keys if key in self.props}

    def run(self, name, *args):
        if name == "dpkg-query" and args == ("-W", "-f=${db:Status-Status}\n${Version}\n${Conffiles}\n", "ufw"):
            return self.package
        prefix = ("--system", "--json=short", "get-property", "org.freedesktop.systemd1",
                  "/org/freedesktop/systemd1/unit/ufw_2eservice")
        if name != "busctl" or args[:5] != prefix or len(args) != 7:
            raise AssertionError("unbounded command")
        interface = "org.freedesktop.systemd1.Unit" if args[-1] == "Job" else "org.freedesktop.systemd1.Service"
        if args[5] != interface or args[-1] not in self.bus:
            raise AssertionError("unbounded property")
        return json.dumps(self.bus[args[-1]]).encode()

    def backend_identity(self, name):
        return self.backends[name]


def loaders():
    return {"ufw.service": {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"},
            "nftables.service": {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"},
            "firewalld.service": {"LoadState": "not-found", "ActiveState": "inactive", "UnitFileState": ""}}


class UfwQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.u = importlib.import_module("deploy.wazuh.https_setup.ufw")
        except ModuleNotFoundError:
            cls.u = None

    def setUp(self):
        self.assertIsNotNone(self.u, "read-only UFW qualification is not implemented")
        self.r = FakeReader(self.u)
        self.loaders = loaders()

    def qualify(self):
        return self.u.qualify_disabled_ufw(self.r, self.loaders)

    def reject(self, code="ufw_unsupported"):
        with self.assertRaises(self.u.SetupError) as caught:
            self.qualify()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def body(self, path, value):
        self.r.files[path] = snapshot(self.u, path, value)

    def test_disabled_vendor_is_admitted_without_bodies_or_volatile_identity(self):
        result = self.qualify()
        self.assertEqual(set(result), {"schema_version", "package_version", "files", "unit", "backends"})
        self.assertEqual(result["package_version"], "0.36.2-6")
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["unit"]["ExecStart"], ["/usr/lib/ufw/ufw-init", "start", "quiet"])
        self.assertEqual(result["unit"]["ExecStop"], ["/usr/lib/ufw/ufw-init", "stop"])
        for entry in result["files"].values():
            self.assertEqual(set(entry), {"path", "sha256", "uid", "gid", "mode", "size"})
        serialized = json.dumps(result)
        for forbidden in ("ENABLED=no", "st_ino", "mtime", "PID", "body", "active", "exited"):
            self.assertNotIn(forbidden, serialized)
        self.u.verify_disabled_ufw(self.r, self.loaders, result)

    def test_executable_shell_and_non_ascii_whitespace_refuse(self):
        for content in (b"ENABLED=no\nLOGLEVEL=low\nid\n", b"ENABLED=no;id\nLOGLEVEL=low\n",
                        b"ENABLED=no\nLOGLEVEL=$(id)\n", b"ENABLED=no\nLOGLEVEL=`id`\n",
                        b"ENABLED=no\nLOGLEVEL=low\n. /tmp/hook\n", b"ENABLED=no\nLOGLEVEL=low\nexec id\n",
                        b"ENABLED=no\nENABLED=no\nLOGLEVEL=low\n", b"ENABLED=no\nLOGLEVEL=low\nX=yes\n",
                        b"export ENABLED=no\nLOGLEVEL=low\n", b"ENABLED='no'\nLOGLEVEL=low\n",
                        b"ENABLED=yes\nLOGLEVEL=low\n", b"ENABLED=no\n", b"ENABLED=no\r\nLOGLEVEL=low\r\n",
                        b"ENABLED=no\nLOGLEVEL=low\n\xc2\xa0id\n", b"\xef\xbb\xbf#comment\nENABLED=no\nLOGLEVEL=low\n",
                        b"ENABLED=no\nLOGLEVEL=low\n\x0bid\n", b"ENABLED=no\nLOGLEVEL=low\n\x00"):
            with self.subTest(content=content):
                self.body("/etc/ufw/ufw.conf", content)
                self.reject()

    def test_literal_comments_and_known_log_levels_are_data(self):
        for level in ("off", "low", "medium", "high", "full"):
            self.body("/etc/ufw/ufw.conf", ("# comment ; $(unused)\n\tENABLED=no # disabled\nLOGLEVEL=" + level + "\n").encode())
            self.qualify()

    def test_untrusted_snapshot_metadata_refuses(self):
        path = "/etc/ufw/ufw.conf"
        for fields in ({"st_mode": stat.S_IFLNK | 0o644}, {"st_mode": stat.S_IFDIR | 0o755},
                       {"st_uid": 1}, {"st_gid": 1}, {"st_mode": stat.S_IFREG | 0o664},
                       {"st_nlink": 2}, {"st_size": 1}, {"st_size": 1048577}):
            with self.subTest(fields=fields):
                self.r.files[path] = snapshot(self.u, path, b"ENABLED=no\nLOGLEVEL=low\n", **fields)
                self.reject()
        self.r.files[path] = replace(snapshot(self.u, path, b"ENABLED=no\nLOGLEVEL=low\n"), canonical_path="/tmp/ufw.conf")
        self.reject()

    def test_actual_oversized_empty_or_missing_snapshot_refuses(self):
        for body in (b"", b"#" + b"x" * 1048576 + b"\nENABLED=no\nLOGLEVEL=low\n"):
            self.body("/etc/ufw/ufw.conf", body)
            self.reject()
        del self.r.files["/etc/ufw/ufw.conf"]
        self.reject()

    def test_trusted_io_error_keeps_fixed_code(self):
        def unreadable(path, limit):
            raise self.u.SetupError("path_untrusted")
        self.r.root_file = unreadable
        self.reject("path_untrusted")

    def test_package_scripts_unit_default_and_hooks_are_pinned(self):
        # ufw.conf is deliberately parsed as data, so a new valid comment is
        # supported at qualification and is separately caught by verification.
        for path in tuple(p for p in self.r.files if p != "/etc/ufw/ufw.conf"):
            with self.subTest(path=path):
                original = self.r.files[path]
                self.body(path, original.body + b"# changed\n")
                self.reject()
                self.r.files[path] = original
        for package in (self.r.package.replace(b"0.36.2-6", b"0.36.2-7"), self.r.package.replace(b"installed", b"config-files"), b"installed\n0.36.2-6\n"):
            self.r.package = package
            self.reject()

    def test_local_package_reference_cannot_bless_custom_code(self):
        path = "/usr/lib/ufw/ufw-init"
        old = hashlib.md5(self.r.files[path].body).hexdigest().encode()
        self.body(path, b"#!/bin/sh\nexit 0\n")
        new = hashlib.md5(self.r.files[path].body).hexdigest().encode()
        sums = self.r.files["/var/lib/dpkg/info/ufw.md5sums"].body.replace(old, new)
        self.body("/var/lib/dpkg/info/ufw.md5sums", sums)
        self.reject()

    def test_executable_or_custom_hooks_refuse(self):
        for name in ("before.init", "after.init"):
            p = "/etc/ufw/" + name
            original = self.r.files[p]
            self.r.files[p] = snapshot(self.u, p, original.body, 0o750)
            self.reject()
            self.r.files[p] = original

    def test_independent_bus_arrays_do_not_infer_empty_from_omission(self):
        self.qualify()  # systemctl's omitted arrays require typed zero from D-Bus.
        for key in ("ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStopPost", "ExecReload",
                    "Environment", "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment"):
            with self.subTest(key=key):
                original = self.r.bus[key]
                self.r.bus[key] = {"type": original["type"], "data": ["injected"]}
                self.reject()
                self.r.bus[key] = {"type": "s", "data": []}
                self.reject()
                self.r.bus[key] = original
        self.r.bus["ExecStartPre"] = {"type": "a(sasbttttuii)"}
        self.reject()

    def test_effective_commands_reject_injection_flags_and_unknown_shapes(self):
        for key in ("ExecStartEx", "ExecStopEx"):
            for field, value in ((0, "/bin/sh"), (1, ["/bin/sh", "-c", "id"]), (2, ["ignore-failure"]),
                                 (3, "unknown"), (3, -1), (3, 2**64), (7, 2**32), (8, 2**31), (9, True)):
                with self.subTest(key=key, field=field):
                    original = copy.deepcopy(self.r.bus[key])
                    self.r.bus[key]["data"][0][field] = value
                    self.reject()
                    self.r.bus[key] = original
            original = self.r.bus[key]
            self.r.bus[key] = {"type": original["type"], "data": []}
            self.reject()
            self.r.bus[key] = original

    def test_runtime_unknown_busy_dirty_and_transient_refuse(self):
        for key, value in (("ActiveState", "reloading"), ("SubState", "running"), ("Transient", "yes"),
                           ("NeedDaemonReload", "yes"), ("Type", "simple"), ("RemainAfterExit", "no"),
                           ("User", "nobody"), ("Group", "nobody"), ("DropInPaths", "/tmp/injected.conf"),
                           ("RootDirectory", "/tmp/root"), ("RootImage", "/tmp/image"), ("PAMName", "login")):
            with self.subTest(key=key):
                old = self.r.props[key]
                self.r.props[key] = value
                self.reject()
                del self.r.props[key]
                self.reject()
                self.r.props[key] = old
        self.r.bus["Job"]["data"] = [1, "/org/freedesktop/systemd1/job/1"]
        self.reject()

    def test_conflicting_and_unknown_loaders_refuse(self):
        for key, field, value in (("nftables.service", "ActiveState", "active"), ("firewalld.service", "UnitFileState", "enabled"),
                                  ("ufw.service", "UnitFileState", "disabled"), ("ufw.service", "LoadState", "not-found")):
            original = self.loaders[key][field]
            self.loaders[key][field] = value
            self.reject()
            self.loaders[key][field] = original
        del self.loaders["nftables.service"]
        self.reject()

    def test_legacy_mixed_and_untrusted_backends_refuse(self):
        original = copy.deepcopy(self.r.backends)
        for name in ("iptables", "ip6tables"):
            for version in (name + " v1.8.10 (legacy)\n", name + " v1.8.9 (nf_tables)\n", "unknown\n"):
                self.r.backends[name]["version"] = version.encode()
                self.reject()
                self.r.backends = copy.deepcopy(original)
            self.r.backends[name]["file"] = snapshot(self.u, "/tmp/xtables-nft-multi", b"foreign", 0o755)
            self.reject()
            self.r.backends = copy.deepcopy(original)
        self.r.backends["ip6tables"]["file"] = snapshot(self.u, "/usr/sbin/xtables-nft-multi", b"different", 0o755)
        self.reject()

    def test_volatile_stat_and_exec_times_do_not_cause_drift(self):
        expected = self.qualify()
        p = "/etc/ufw/ufw.conf"
        self.r.files[p] = snapshot(self.u, p, self.r.files[p].body, st_ino=999, st_dev=888, st_mtime=555, st_ctime=666)
        self.r.bus["ExecStartEx"]["data"][0][3:] = [11, 22, 33, 44, 55, 0, 0]
        self.u.verify_disabled_ufw(self.r, self.loaders, expected)

    def test_static_change_and_ineligible_runtime_refuse_every_verification(self):
        expected = self.qualify()
        self.body("/etc/ufw/ufw.conf", b"# changed but valid\nENABLED=no\nLOGLEVEL=low\n")
        with self.assertRaises(self.u.SetupError) as caught:
            self.u.verify_disabled_ufw(self.r, self.loaders, expected)
        self.assertEqual(caught.exception.code, "ufw_drift")
        self.r = FakeReader(self.u)
        self.r.props["NeedDaemonReload"] = "yes"
        with self.assertRaises(self.u.SetupError) as caught:
            self.u.verify_disabled_ufw(self.r, self.loaders, expected)
        self.assertEqual(caught.exception.code, "ufw_unsupported")

    def test_partial_unknown_or_malformed_expected_record_refuses(self):
        expected = self.qualify()
        tuple_array = copy.deepcopy(expected)
        tuple_array["unit"]["ExecStart"] = tuple(tuple_array["unit"]["ExecStart"])
        invalid = [None, {}, [], {**expected, "unknown": True}, {**expected, "schema_version": True},
                   {**expected, "files": {}}, {**expected, "unit": {}}, {**expected, "backends": {}}, tuple_array]
        for value in invalid:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(self.u.SetupError) as caught:
                    self.u.verify_disabled_ufw(self.r, self.loaders, value)
                self.assertEqual(caught.exception.code, "ufw_drift")


if __name__ == "__main__":
    unittest.main()
