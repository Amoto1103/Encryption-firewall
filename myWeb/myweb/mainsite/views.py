# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse,Http404
from .models import Rule,IP
import subprocess
# Create your views here.

def viewRule(request):
	html='''
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>防火墙规则列表</title>
</head>
<body>
<h2>以下是防火墙规则列表，可以选择一个ID对应的规则运行防火墙</h2>
<hr>
<table width=400 border=1 bgcolor='ccffcc'>
{}
</table>
</body>
</html>
'''
	rules=Rule.objects.all()
	tags='<tr><td>防火墙规则功能</td><td>规则ID</td></tr>'
	for p in rules:
		tags=tags+'<tr><td>{}</td>'.format(p.name)
		tags=tags+'<td>{}</td></tr>'.format(p.id)
	return HttpResponse(html.format(tags))

def viewIP(request):
	html='''
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>运行此防火墙IP地址列表</title>
</head>
<body>
<h2>以下是所有运行本防火墙的主机IP地址列表</h2>
<hr>
<table width=400 border=1 bgcolor='ccffcc'>
{}
</table>
</body>
</html>
'''
	IPs=IP.objects.all()
	tags='<tr><td>序号</td><td>主机IP地址</td></tr>'
	for p in IPs:
		tags=tags+'<tr><td>{}</td>'.format(p.id)
		tags=tags+'<td>{}</td></tr>'.format(p.IPaddress)
	return HttpResponse(html.format(tags))

def homepage(request):
	rules=Rule.objects.all()
	IPs=IP.objects.all()
	
	html='''
<!DCCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>欢迎使用基于netfilter的应用层网络加密通信系统</title>
<style type="text/css">
a
{
	color:red;
	text-decoration:none;
}
a:hover
{
	color:blue;
	text-decoration:underline;
}
</style>
<script>
function getinfo()
{
	document.write("rr")
}
</script>
</head>
<body>
<h1>欢迎使用基于netfilter的应用层网络加密通信系统</h1>
<hr>
<div>
<a href="http://127.0.0.1:8000/rules/" target="_blank">查看防火墙规则集</a>
</div>
<div>
<a href="http://127.0.0.1:8000/ips/" target="_blank">查看运行此防火墙的IP地址合集</a>
</div>
<div>
<a href="http://127.0.0.1:8000/admin/" target="_blank">前往管理员页面修改规则集和IP地址</a>
</div>
<form name="myform" action='/' method='GET'>
<label for='rule_id'>输入你想要执行的规则序号:</label>
<input id='rule_id' type='text' name='rule_id'>
<input type='submit' value='开始运行防火墙'>
</form>
</body>
</html>
'''
	return HttpResponse(html)

def getinformation(request,ID):
	html='''
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>getinfo</title>
</head>
<body>
<h2>{}</h2>
<h2>{}</h2>
<h2>{}</h2>
<h2>{}</h2>
<h2>{}</h2>
<h2>{}</h2>
<h2>{}</h2>
</body>
</html>
'''
	try:
		p=Rule.objects.get(id=ID)
	except Rule.DoesNotExist:
		raise Http404('NOT FOUND!')
	process1=subprocess.Popen(['iptables','-t','mangle','-A','INPUT','-j','NFQUEUE','--queue-num','1'])
	process1=subprocess.Popen(['iptables','-t','mangle','-A','OUTPUT','-j','NFQUEUE','--queue-num','2'])
	process = subprocess.Popen(['/home/qqq/Desktop/filter.out',str(p.protocol),str(p.sourceIP),str(p.sourcePort),str(p.desIP),str(p.desPort)])
	return HttpResponse(html.format(p.name,p.id,p.sourceIP,p.sourcePort,p.desIP,p.desPort,p.protocol))

