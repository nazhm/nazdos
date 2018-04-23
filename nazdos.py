#----------imports----------#
import re #regular expression module
import csv #export to csv module
import fileinput
import time
import matplotlib
import matplotlib.pyplot as plt #for graph
from matplotlib import pyplot
from pylab import genfromtxt
import numpy as np
import sys #for image generators/printers
from PIL import Image #for image generators/printers
import smtplib #importing library for email feature
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import shutil


#----------Config File----------#
with open('nazdosconfig.csv', 'r') as nazdosConfig :
	for line in nazdosConfig.readlines():
		if line.startswith('Upper threshold: '):
			upperThreshold = line.replace('Upper threshold: ','').strip()
		if line.startswith('Lower threshold: '):
			lowerThreshold = line.replace('Lower threshold: ','').strip()
		if line.startswith('Email Graphs, Log file, Prevention file and DDoS event details: '):
			emailEvent = line.replace('Email Graphs, Log file, Prevention file and DDoS event details: ','').strip()		#1=email, 0=don't email...
		if line.startswith('Email to: '):
			emailTo = line.replace('Email to: ','').strip()
		if line.startswith('Email from: '):
			emailFrom = line.replace('Email from: ','').strip()
		if line.startswith('Email password: '):
			emailPassword = line.replace('Email password: ','').strip()
		if line.startswith('Log file name: '):
			logName = line.replace('Log file name: ','').strip()
		if line.startswith('Email subject: '):
			emailTitle = line.replace('Email subject: ','').strip()
		if line.startswith('Email message: '):
			emailBody = line.replace('Email message: ','').strip()
		if line.startswith('Print graphs dashboard each detection: '):
			printGraphs = line.replace('Print graphs dashboard each detection: ','').strip()
nazdosConfig.close()

#----------open/read log----------#
log = open(logName,'r') #open log
read = log.read() #read log


#----------search via reg expressions----------#
httpRE='HTTP/[\d.]+"\s+(\d{3})' #reg expression for http status codes - original
statusCodes = re.findall(httpRE,read) #search for reg expression


#----------count reg expressions----------#
statusCodesCounter = {}
for i in statusCodes:
    statusCodesCounter[i] = statusCodes.count(i)


#----------Count the total number of requests----------#
newTotal = 0
for i in statusCodesCounter:
	newTotal = newTotal + statusCodesCounter[i]


#----------Translating dictionary (statusCodesCounter) to string (old200 etc)----------#
new = statusCodesCounter
locals().update(new)


#---------Initialising log file----------# **********
old408 = 0
old404 = 0
old400 = 0


#----------Threshold checker----------#
#---Read old status codes---#
with open('lastRun.csv', 'r') as configFile :
	for line in configFile.readlines():
		#---Storing old status codes in variables (e.g. old value for status code 200 is stored in the variable old200)---#		
		if line.startswith('Total'):
			oldTotal = line.replace('Total,','')

		if line.startswith('408'):
			old408 = line.replace('408,','')

		if line.startswith('404'):
			old404 = line.replace('404,','')

		if line.startswith('400'):
			old400 = line.replace('400,','')	
configFile.close()


#----------Printing currentRun-----------# 
#---Prints everything into currentRun---#
with open('currentRun.csv', 'wb') as csvfile:
    writer = csv.writer(csvfile)
    header = ['status code', 'frequency']
    writer.writerow(header)
    for i in statusCodesCounter:
        writer.writerow((i, statusCodesCounter[i]))
csvfile.close()

#---Also print the total number of requests to the CSV file---#
f = open('currentRun.csv','a')
print >>f, 'Total,' + str(newTotal)
f.close()

slowlorisPrev = 0
httpfloodPrev = 0

#----------Threshold----------# testing github testing upload
try:
#408 (Slowloris)
	#Surplis
	f = open('NazdosSummary.csv','a')
	if new['408'] > float(old408)*float(lowerThreshold): #if the new count of the status code is 1.6x greater than the existing one:
		print '408 too high (Slowloris)'
		slowlorisPrev = 1
		#f = open('NazdosSummary.csv','a')
		print >>f, time.strftime("%d/%m/%Y,%H:%M:%S,408,") + ('%s')% old408.strip() + ',' + ('%s')% new['408'] + ',Surplus,' + 'Slowloris'	
#Total (HTTP Flood)
	#Surplus
	if newTotal > float(oldTotal)*float(upperThreshold): #if the new count of the status code is 1.6x greater than the existing one:
		print 'Total too high (HTTP Flood)'
		httpfloodPrev = 1
		#f = open('NazdosSummary.csv','a')
		print >>f, time.strftime("%d/%m/%Y,%H:%M:%S,Total,") + ('%s')% oldTotal.strip() + ',' + ('%s')% newTotal + ',Surplus,' + 'HTTP Flood'
	#Decline
	if newTotal < float(oldTotal)*float(upperThreshold):
		print 'Total too low (DDOS)'
		httpfloodPrev = 1
		#f = open('NazdosSummary.csv','a')
		print >>f, time.strftime("%d/%m/%Y,%H:%M:%S,Total,") + ('%s')% oldTotal.strip() + ',' + ('%s')% newTotal + ',Deficit,' + 'Server down'
	f.close()
except Exception as e:
	print '...'

if str(slowlorisPrev) == '1' and str(httpfloodPrev) == '1':
	bothDoc = 'httpfloodandslowloris_prevention.pdf'
if str(slowlorisPrev) == '1' and str(httpfloodPrev) == '0':
	bothDoc = 'slowloris_prevention.pdf'
if str(slowlorisPrev) == '0' and str(httpfloodPrev) == '1':
	bothDoc = 'httpflood_prevention.pdf'
if str(slowlorisPrev) == '0' and str(httpfloodPrev) == '0':
	bothDoc = 'httpfloodandslowloris_prevention.pdf'

print 'slowlorisPrev: ' + str(slowlorisPrev)	
print bothDoc
#----------Scatter Graph comparing ALL requests for lastRun and currentRun----------#
try:
	scatter1 = genfromtxt("currentRun.csv", delimiter=',');
	scatter2 = genfromtxt('lastRun.csv', delimiter=',');
	pyplot.scatter(scatter1[:,0], scatter1[:,1], label = "Current Run",color='green');
	pyplot.scatter(scatter2[:,0], scatter2[:,1], label = "Last Run",color='red');
	pyplot.legend();
	pyplot.title('Comparison of traffic', fontsize=12)
	pyplot.xlabel('Requests', fontsize=10)
	pyplot.ylabel('Occurrences', fontsize=10)
	#pyplot.show(block=False);
	#pyplot.grid(True, zorder=5, color='black')
	pyplot.savefig('allRequests.jpg', bbox_inches='tight')
	pyplot.close()
except Exception as e:
	print 'graph 1'
	shutil.copy2('noData.jpg', 'allRequests.jpg')


#----------Bar Chart comparing KEY requests for lastRun and currentRun----------#
try:
	old408D = {'Total':int(oldTotal), 408:int(old408), 404:int(old404), 400:int(old400)}
	new408D = {'Total':int(newTotal),   408:int(new['408']),  404:int(new['404']),    400:int(new['400'])}

	Xaxis = np.arange(len(old408D))
	ax = plt.subplot(111)
	ax.bar(Xaxis, old408D.values(), width=0.2, color='red', align='center')
	ax.bar(Xaxis-0.2, new408D.values(), width=0.2, color='green', align='center')#should be CURRENT
	ax.legend(('Last Run','Current Run'))
	plt.xticks(Xaxis, old408D.keys())
	plt.title("Comparison of key traffic", fontsize=12)
	pyplot.xlabel('Requests', fontsize=10)
	pyplot.ylabel('Occurrences', fontsize=10)
	#pyplot.grid(True, zorder=5, color='grey')
	plt.savefig('408Requests.jpg', bbox_inches='tight')
	plt.close()
except Exception as e:
	print 'graph 2'
	shutil.copy2('noData.jpg', '408Requests.jpg')

#----------Slowloris graph----------#
try:
	old408D = {408:int(old408)}
	new408D = {408:int(new['408'])}

	Xaxis = np.arange(len(old408D))
	ax = plt.subplot(111)
	ax.bar(Xaxis, old408D.values(), width=0.2, color='red', align='center')
	ax.bar(Xaxis-0.2, new408D.values(), width=0.2, color='green', align='center')#should be CURRENT

	ax.legend(('Last Run','Current Run'))
	plt.xticks(Xaxis, old408D.keys())
	plt.title("Slowloris analysis", fontsize=12) 
	pyplot.xlabel('408 Requests', fontsize=10)
	pyplot.ylabel('Occurrences', fontsize=10)
	ax.invert_yaxis() 
	plt.savefig('slowlorisRequests.jpg', bbox_inches='tight')
	plt.close()
except Exception as e:
	print 'graph 3'
	shutil.copy2('noData.jpg', 'slowlorisRequests.jpg')

#----------HTTP flood graph----------#
try:
	old408D = {'Total':int(oldTotal)}
	new408D = {'Total':int(newTotal)}

	X = np.arange(len(old408D))
	ax = plt.subplot(111)
	ax.bar(X, old408D.values(), width=0.2, color='red', align='center')
	ax.bar(X-0.2, new408D.values(), width=0.2, color='green', align='center')#should be CURRENT

	ax.legend(('Last Run','Current Run'))
	plt.xticks(X, old408D.keys())
	plt.title("HTTP Flood analysis", fontsize=12)
	pyplot.xlabel('Requests', fontsize=10)
	pyplot.ylabel('Occurrences', fontsize=10)
	ax.invert_yaxis() 
	plt.savefig('httpfloodRequests.jpg', bbox_inches='tight')
except Exception as e:
	print 'graph 4'
	shutil.copy2('noData.jpg', 'httpfloodRequests.jpg')

#----------Updating lastRun-----------# 
#---Prints everything into lastRun---#
with open('lastRun.csv', 'wb') as csvfile:
    writer = csv.writer(csvfile)
    header = ['status code', 'frequency']
    writer.writerow(header)
    for i in statusCodesCounter:
        writer.writerow((i, statusCodesCounter[i]))   
csvfile.close()    
#---Also print the total number of requests to the CSV file---#
f = open('lastRun.csv','a')
print >>f, 'Total,' + str(newTotal)
f.close()

#---------- Image Generators ----------#
#---Generate new image by combining images generated from previous graphs---#
dashboard = map(Image.open, ['allRequests.jpg', 'Bar.jpg','408Requests.jpg', 'Bar.jpg', 'slowlorisRequests.jpg', 'Bar.jpg', 'httpfloodRequests.jpg']) #Open separate images
maxWidth, maxHeight = zip(*(dim.size for dim in dashboard)) #set dimensions for images
#
maximumWidth = sum(maxWidth) #set max width
maximumHeight = max(maxHeight) #set max height
#
dashboardImage = Image.new('RGB', (maximumWidth, maximumHeight)) #create new image with the defined width/height
#
dimensionX = 0
for dashboardPic in dashboard:
  dashboardImage.paste(dashboardPic, (dimensionX,0))
  dimensionX += dashboardPic.size[0]
#
dashboardImage.save('dashboardImage.jpg') #save new image
#

#----------open image that was generated IF user sets it to 0----------#
if str(printGraphs) == 'y': #AKA if this value is 0, run code.
	dashboardImg = Image.open('dashboardImage.jpg')
	dashboardImg.show()

##----------save everything in log file to a new log file----------#
#with open(logName, "w") as fw, open("entireLogFile.txt","r") as fr: 
#    fw.writelines(l for l in fr if "tests/file/myword" in l)

#----------Clearing the log file----------#
open(logName, 'w').close()


#----------Emailing message & 2 attachments (dashboardImage.jpg and csv log file)----------#
if (str(emailEvent) == 'y' and str(httpfloodPrev) == '1') or (str(emailEvent) == 'y' and str(slowlorisPrev) == '1'): #if this value (which comes from configB.csv's "Email Graphs, Log file and DDoS event details:" line) is 1, run this code...
#if (str(emailEvent) == 'y') and ((str(httpfloodPrev) == '1') or (str(slowlorisPrev) == '1')): #if this value (which comes from configB.csv's "Email Graphs, Log file and DDoS event details:" line) is 1, run this code...
	print 'The results were successfully emailed.'

#--User email credentials--#
	emailSender = emailFrom
	emailRecipient = emailTo
	emailSubject = emailTitle

#--from/to/subject--#
	newEmail = MIMEMultipart() #define new multipart object
	newEmail['From'] = emailSender
	newEmail['To'] = emailRecipient
	newEmail['Subject'] = emailSubject 

#--Prepare email content--#
	emailMessage = emailBody #setting up the content that I will send
#--MIMEText part attachment--#
	newEmail.attach(MIMEText(emailMessage,'plain'))

#---Dashboard---#
#--Open image file--#
	imageFile = 'dashboardImage.jpg'
	imageAttachment = open(imageFile,'rb')
#--Prepare connection to attach image file--#
	attachment1 = MIMEBase('application','octet-stream') #opening stream to upload attachment/sendit/close stream
	attachment1.set_payload((imageAttachment).read()) #reading contents of attachment
	encoders.encode_base64(attachment1) #set as base64
	attachment1.add_header('Content-Disposition','attachment; filename= ' + imageFile) #set headers of file

#---Nazdos Summary CSV---#
#--Open CSV file--#
	csvLogFile = 'nazdossummary.csv'
	csvLogAttachment = open(csvLogFile,'rb')
#--Prepare connection to attach CSV file--#
	attachment2 = MIMEBase('application','octet-stream') #opening stream to upload attachment/sendit/close stream
	attachment2.set_payload((csvLogAttachment).read()) #reading contents of attachment
	encoders.encode_base64(attachment2) #set as base64
	attachment2.add_header('Content-Disposition','attachment; filename= ' + csvLogFile) #set headers of file

#---Prevention PDF---#
#--Open pdf file--#
#	slowlorisDoc = 'slowloris_prevention.pdf'
	slowlorisDocAttachment = open(bothDoc,'rb')
#--Prepare connection to attach CSV file--#
	attachment3 = MIMEBase('application','octet-stream') #opening stream to upload attachment/sendit/close stream
	attachment3.set_payload((slowlorisDocAttachment).read()) #reading contents of attachment
	encoders.encode_base64(attachment3) #set as base64
	attachment3.add_header('Content-Disposition','attachment; filename= ' + bothDoc) #set headers of file

#--Attach image & CSV files file--#
	newEmail.attach(attachment1) #attach image file
	newEmail.attach(attachment2) #attach CSV file
	newEmail.attach(attachment3) #slowloris .Docx file
#	newEmail.attach(attachment4) #httpflood .Docx file
#-- Wrap email oontent in a string--#
	emailContent = newEmail.as_string() #everything is set as string

#Connect to server
	gmailServer = smtplib.SMTP('smtp.gmail.com',587) #choosing the smtp mail server (smtp.gmail.com) and port (587, can be 465)
	gmailServer.ehlo() #identifying to server ('helo' for normal server or 'ehlo' extended smtp server)
	gmailServer.starttls() #start TLS mode, AKA transport layer security mode, to encrypt login data
	gmailServer.login('nazdosalert@gmail.com','FinallyFree221')
	gmailServer.sendmail('nazdosalert@gmail.com','nazdosalert@gmail.com',emailContent) #parameters are: 'from_email','to_email','content'
	gmailServer.close()


#----------Date, Time----------#
print (time.strftime("%d/%m/%Y, %H:%M:%S"))