### Create plots and tables
plot2file = function(filename,expr,width=17.35,height=8.3,units="cm",pointsize=8,res=150,...) {
  tiff(filename,width=width,height=height,units=units,pointsize=pointsize,res=res)
  par(...)
  tryCatch(eval(expr),finally=dev.off())
}

### Create plots and tables (NB: units are in inches)
plot2eps = function(filename,expr,width=6.83,height=3.27,pointsize=8,...) {
  setEPS()
  postscript(filename,width=width,height=height,pointsize=pointsize)
  par(...)
  tryCatch(eval(expr),finally=dev.off())
}

# Steelpan plot (2 lineages)
plot.pos.sel = function(gamma.file, anc.file, seqs.file1, seqs.file2, genename="") {
  ppos = read.table(gamma.file,head=TRUE,as.is=TRUE,sep="\t")
  anc = read.table(anc.file,head=TRUE,as.is=TRUE,sep="\t")
  seqs1 = read.fasta(seqs.file1,as.char=TRUE)
  seqs2 = read.fasta(seqs.file2,as.char=TRUE)
# Calculate conversions
  cdanc = apply(anc,2,function(x)names(sort(table(x),decreasing=TRUE))[1])
  aaanc = as.vector(translate(matrix(cdanc,nrow=1)))
  cd1 = transcribe(seqs1)
  cd2 = transcribe(seqs2)
  aa1 = translate(cd1)
  aa2 = translate(cd2)
  pos1 = apply(ppos[,ncol(aa1)*(1-1)+1:ncol(aa1)]>0,2,mean)
  pos2 = apply(ppos[,ncol(aa1)*(2-1)+1:ncol(aa1)]>0,2,mean)
  gcode = names(geneticCode)[geneticCode!="STO"]
  acode = unlist(geneticCode[geneticCode!="STO"])
# Identify the major (codon) allele for each species at each site
# Major allele
  mj1 = apply(cd1,2,function(y) which.max(table(factor(y,levels=gcode))))
  mj2 = apply(cd2,2,function(y) which.max(table(factor(y,levels=gcode))))
# Minor synonymous allele frequency (i.e. same aa as major allele)
  ms1 = sapply(1:ncol(cd1),function(j) mean(as.integer(factor(cd1[,j],levels=gcode))!=mj1[j] & aa1[,j]==acode[mj1[j]],na.rm=T))
  ms2 = sapply(1:ncol(cd2),function(j) mean(as.integer(factor(cd2[,j],levels=gcode))!=mj2[j] & aa2[,j]==acode[mj2[j]],na.rm=T))
# Minor nonsynonymous allele frequency (i.e. different aa to major allele)
  mn1 = sapply(1:ncol(cd1),function(j) mean(as.integer(factor(cd1[,j],levels=gcode))!=mj1[j] & aa1[,j]!=acode[mj1[j]],na.rm=T))
  mn2 = sapply(1:ncol(cd2),function(j) mean(as.integer(factor(cd2[,j],levels=gcode))!=mj2[j] & aa2[,j]!=acode[mj2[j]],na.rm=T))
# Fixed differences
  fd1 = which(gcode[mj1]!=cdanc)
  fd2 = which(gcode[mj2]!=cdanc)
  fdpch1 = rep(19,length(fd1))
  fdpch2 = rep(19,length(fd2))
#fdpch[acode[mj[fd]]==aaanc[fd]] = 21
  syncol1 = "green3"
  syncol2 = "lawngreen"
  nsyncol1 = "red"
  nsyncol2 = rgb(255,140,0,max=255)
  fdcol1 = rep(syncol1,length(fd1))
  fdcol1[acode[mj1[fd1]]!=aaanc[fd1]] = nsyncol1
  fdcol2 = rep(syncol2,length(fd2))
  fdcol2[acode[mj2[fd2]]!=aaanc[fd2]] = nsyncol2
  fd = c(fd1,fd2)
  fdpch = c(fdpch1,fdpch2)
  fdcol = c(fdcol1,fdcol2)
  fdp = fdcol==nsyncol1 | fdcol==nsyncol2
# Plot it
  tb = rbind(ms1,mn1,ms2,mn2)
  colnames(tb) <- 1:ncol(tb)
  NAMES = rep(NA,length(pos1)); NAMES[1]=1; NAMES[seq(50,length(pos1),by=50)]=seq(50,length(pos1),by=50)
  bp = barplot(tb,col=c(syncol1,nsyncol1,syncol2,nsyncol2),border=NA,ylim=c(0,1.09),xlab="",ylab="",main="",xaxs="i",names=NAMES)
  lines(bp[fd[!fdp]],rep(1.05,length(fd[!fdp])),type="p",pch=fdpch[!fdp],col=fdcol[!fdp],xpd=TRUE)
  lines(bp[fd[fdp]],rep(1.05,length(fd[fdp])),type="p",pch=fdpch[fdp],col=fdcol[fdp],xpd=TRUE)
  lines(bp,pos1,type="l",lwd=0.5,col="black")
  lines(bp,pos2,type="l",lwd=0.5,col="grey")
  axis(1,c(-1000,bp[!is.na(NAMES)],1000),c("",rep("",sum(!is.na(NAMES))),""))
  axis(4)
  mtext(expression(paste("Pr(",gamma>0,")")),2,2.5,las=3)
  mtext("Codon",1,2.5)
  mtext("Minor allele frequency",4,2.8,las=3)
  mtext(genename,line=0.5,font=1,cex=10/8)
  invisible(bp)
}
