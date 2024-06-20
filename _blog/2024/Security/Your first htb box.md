---
layout: blog
title: Creating your first box for HTB
tags: Windows Linux Active-Directory Content-Creation SysAdmin
comments: true
date: 2024-06-20
---
# Creating your first box for HackTheBox
## Introduction
Content creation is a whole new world. As in everything on IT, you need a methodology, and to be honest, there's no much teaching about methodology publicly. Creating content for HTB is more an art than a science, wise words by [ctrlzero](https://www.hackthebox.com/blog/building-your-first-htb-machine). On that blog, he explains really well how's about the methodology when creating a box for the platform, and I do agree with him; I was very lucky when I started building boxes for HTB, since at my early beginning, TheCyberGeek led me into the right methodology to do things and be as fast and as original as possible. On this post, I'll share the methodology I use to build my boxes, and we'll see how to setup a real AD laboratory which on later posts we'll pop up. We'll keep in mind that everything is realistic and makes sense to the lab.

> Disclaimer: HTB has strict policies about reusing vulnerabilities for new boxes, so, on this post I won't use vulns that are not used yet for any other box, i.e.: I'll use for example, vulnerabilities that are already used like ESC1, CVE-2024-1086 and so on.

