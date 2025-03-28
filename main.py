from fasthtml.common import *
from starlette.responses import FileResponse
import bcrypt
import base64
import uuid
from docxtpl import DocxTemplate, InlineImage, RichText
from docx.shared import Mm
from generator import parseContext
from enum import Enum
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import csv
import io
import re
import time
import secrets
from password_validator import PasswordValidator

# authentication
login_redir = RedirectResponse('/login', status_code=303)

# password complexity requirements
password_complexity = PasswordValidator().min(8).max(100).has().uppercase().has().lowercase().has().digits().has().symbols().has().no().spaces()

def authenticate(req, sess):
    auth = req.scope['auth'] = sess.get('auth', None)
    if not auth: 
        return login_redir

beforeware = Beforeware(
    authenticate,
    skip=[r'/favicon\.ico', r'/assets/.*', r'.*\.css', r'.*\.js', '/login']
)

app,rt = fast_app(
    # authentication middleware
    before=beforeware,

    # light theme on chrome fix
    hdrs=[
        Script('document.documentElement.setAttribute("data-theme", "light");'),
        Link(rel="icon", href="/assets/icons/favicon.svg"),
        Link(rel="stylesheet", href="/assets/css/cvss.css"),
        Link(rel="stylesheet", href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.colors.min.css"),
        Link(rel="stylesheet", href="/assets/css/custom.css"),
        Style(':root { --pico-font-size: 100%;}'),

    # markdown styling and highliting
    MarkdownJS(),
    HighlightJS(langs=['python', 'javascript', 'html', 'css'])])

# toast setup
setup_toasts(app)

# define and create database objects
db = database('data/main.db')

vulns,reports,issues,users = db.t.vulns,db.t.reports,db.t.issues,db.t.users

if vulns not in db.t:
    vulns.create(id=int, title=str, cvss=str, score=float, severity=str, description=str, poc=str, impact=str, recommendation=str, pk='id')

if reports not in db.t:
    reports.create(id=int, title=str, client=str, start_date=str, end_date=str, retest_date=str, authors=str,  summary=str, scope=str, pk='id')

if issues not in db.t:
    issues.create(id=int, report_id=int, title=str, cvss=str, score=float, severity=str, description=str, poc=str, impact=str, recommendation=str, pk='id')

if users not in db.t:
    users.create(id=int, login=str, password=str, role=str, first_login=bool, pk='login')

Vuln, Report, Issue, User = vulns.dataclass(), reports.dataclass(), issues.dataclass(), users.dataclass()

# get css class for severity
def getSeverityClass(severity):
    cls = ""

    if severity == "Critical":
        cls = "severity-critical"
    if severity == "High":
        cls = "severity-high"
    if severity == "Medium":
        cls = "severity-medium"
    if severity == "Low":
        cls = "severity-low"
    if severity == "Info":
        cls = "severity-info"

    return cls

# dataclass lists decorators
@patch
def __ft__(self:Vuln):
    title = self.title
    severity = self.severity
    edit = A(Img(src='/assets/icons/edit.svg', cls="icon"), href=f'/vulns/edit/{self.id}', data_tooltip='Edit', style='text-underline-offset: 200em')
    delete = A(Img(src='/assets/icons/delete.svg', cls="icon-delete"), hx_delete=f'/vulns/{self.id}', hx_confirm='Do you really want to delete this vulnerability template?', data_tooltip='Delete', style='text-underline-offset: 200em')
    return Details(Summary(Strong(f"{severity}", cls=getSeverityClass(severity)), title, edit, delete, role="button", cls="outline contrast vuln-list"), Strong("Description"), P(self.description, cls="marked"), Strong("Impact"), P(self.impact, cls="marked"), Strong("Recommendation"), P(self.recommendation, cls="marked"))

@patch
def __ft__(self:Report):
    show = A(self.title, href=f'/reports/{self.id}', cls='contrast')
    view = A(Img(src='/assets/icons/view.svg', cls="icon"), href=f'/reports/{self.id}', data_tooltip='View')
    edit = A(Img(src='/assets/icons/edit.svg', cls="icon"), href=f'/reports/edit/{self.id}', data_tooltip='Edit')
    delete = A(Img(src='/assets/icons/delete.svg', cls="icon-delete"), hx_delete=f'/reports/{self.id}', hx_confirm='Do you really want to delete this report?', data_tooltip='Delete')
    return Tr(Th(show), Td(self.client), Td(self.start_date), Td(self.authors), Td(view), Td(edit), Td(delete))

@patch
def __ft__(self:Issue):
    title = self.title
    severity = self.severity
    view = A(Img(src='/assets/icons/view.svg', cls="icon"), href=f'/issues/{self.id}', data_tooltip='View', style='text-underline-offset: 200em')
    edit = A(Img(src='/assets/icons/edit.svg', cls="icon"), href=f'/issues/edit/{self.id}', data_tooltip='Edit', style='text-underline-offset: 200em')
    delete = A(Img(src='/assets/icons/delete.svg', cls="icon-delete"), hx_delete=f'/issues/{self.id}', hx_confirm='Do you really want to delete this issue?', data_tooltip='Delete', style='text-underline-offset: 200em')

    return (
        Details(
            Summary(Strong(f"{severity}", cls=getSeverityClass(severity)), title, edit, delete, role="button", cls="outline contrast issue-list"), Strong("Description"), P(self.description, cls="marked"), Strong("Impact"), P(self.impact, cls="marked"), Strong("Recommendation"), P(self.recommendation, cls="marked"), Strong("Technical details"), P(self.poc, cls="marked")))

# defined inputs

## add new vulnerability template
def new_vuln_input(**kw): 
    return (
        H2("Add vulnerabilty template"), Pre(),
        
        Strong("Title"), 
        Input(id="new-title", name="title", placeholder="Add vulnerability title", **kw), Pre(),
        
        Strong("Description"),
        Textarea(id="editor-description", name="description", placeholder="Add vulnerability desctiption", **kw), Pre(), 
        
        Strong("CVSS Vector"), 
        Div(Hidden(id="issue-cvss", name="cvss"),
            Hidden(id="issue-score", name="score"), id="cvssboard", style="none"),
        P(Br()),
        
        Pre(),
        
        Strong("Severity"), 
        Select(Option("Critical", value="Critical", selected=False), Option("High", value="High", selected=True), Option("Medium", value="Medium", selected=False), Option("Low", value="Low", selected=False), Option("Info", value="Info", selected=False), name="severity", id="new-severity", **kw), Pre(), 

        Strong("Technical details (Proof-of-concept)"),
        Textarea(id="editor-poc", name="poc", placeholder="Add vulnerability technical details", **kw), Pre(),

        Strong("Impact"),
        Textarea(id="editor-impact", name="impact", placeholder="Add vulnerability impact", **kw), Pre(),

        Strong("Recommendation"),
        Textarea(id="editor-recommendation", name="recommendation", placeholder="Add vulnerability recommendation", **kw)), Pre() 

## edit vulnerability template
def edit_vuln_input(**kw): 
    
    isCritical = False 
    isHigh = False
    isMedium = False
    isLow = False
    isInfo = False

    severity = kw.get('severity')

    if severity == "Critical":
        isCritical = True
    if severity == "High":
        isHigh = True
    if severity == "Medium":
        isMedium = True
    if severity == "Low":
        isLow = True
    if severity == "Info":
        isInfo = True

    return (
        H2("Edit vulnerabilty template"), Pre(),
        
        Strong("Title"), 
        Input(id="new-title", name="title", value=kw.get('title'), **kw), Pre(),
        
        Strong("Description"),
        Textarea(id="editor-description", name="description", value=kw.get('description'), **kw), Pre(),
        
        Strong("CVSS Vector"), 
        Div(Hidden(id="issue-cvss", name="cvss", value=kw.get('cvss'), **kw),
            Hidden(id="issue-score", name="score", value=kw.get('score'), **kw), id="cvssboard", style="none"),
        P(Br()),
        
        Strong("Severity"), 
        Select(Option("Critical", value="Critical", selected=isCritical), Option("High", value="High", selected=isHigh), Option("Medium", value="Medium", selected=isMedium), Option("Low", value="Low", selected=isLow), Option("Info", value="Info", selected=isInfo), name="severity", id="new-severity", **kw), Pre(),
        
        Strong("Technical details (Proof-of-concept)"),
        Textarea(id="editor-poc", name="poc", value=kw.get('description'), **kw), Pre(),
        
        Strong("Impact"),
        Textarea(id="editor-impact", name="impact", value=kw.get('impact'), **kw), Pre(),
        
        Strong("Recommendation"),
        Textarea(id="editor-recommendation", name="recommendation", value=kw.get('recommendation'), **kw))

## add new report
def new_report_input():
    return (
        Strong("Title"),
        Input(id="report-title", name="title"),
                    
        Div(
            Div(Strong("Start date"), 
            Input(id="report-start-date", name="start_date", type="date")), 
            
            Div(Strong("End date"),
            Input(id="report-end-date", name="end_date", type="date")), 
            
            Div(Strong("Retest date"),
            Input(id="report-retest-date", name="retest_date", type="date")), 
        
        cls="grid"),

        Div(  
            Div(Strong("Client"), Input(id="report-client", name="client")), 
            Div(Strong("Authors"), Input(id="report-authors", name="authors")),  
        cls="grid"),

        Strong("Summary"),
        Textarea(id="editor-summary", name="summary"),
        
        Strong("Scope"),
        Textarea(id="editor-scope", name="scope"))

## edit report attributes
def reports_attributes_input(**kw): 
    return (
        Hidden(id="id", value=kw.get('id')),
        
        Strong("Title"),
        Input(id="report-title", name="title", value=kw.get('title')),
        
        Strong("Start date"),
        Input(id="report-start-date", name="start_date", type="date", value=kw.get('start_date')),
        
        Strong("End date"),
        Input(id="report-end-date", name="end_date", type="date", value=kw.get('end_date')),
        
        Strong("Retest date"),
        Input(id="report-retest-date", name="retest_date", type="date", value=kw.get('retest_date')),
        
        Strong("Client"),
        Input(id="report-client", name="client", value=kw.get('client')),
        
        Strong("Authors"),
        Input(id="report-authors", name="authors", value=kw.get('authors')),
        
        Strong("Summary"),
        Textarea(id="editor-summary", name="summary"),
        
        Strong("Scope"),
        Textarea(id="editor-scope", name="scope"))

## add new issue
def new_issue_input(**kw): 
    return (
        H2("Add new issue"),
        
        Hidden(id="issue-report-id", name="report_id", value=kw.get('report_id'), **kw),
        
        P(Strong("Title")),
        Input(id="issue-title", name="title", value="Add vulnerability title", **kw),
        
        P(Br()),
        P(Strong("Description")),
        Textarea(id="editor-description", name="description"), 
        
        P(Strong("CVSS Vector")),
        Div(
            Hidden(id="issue-cvss", name="cvss", **kw),
            Hidden(id="issue-score", name="score", **kw), id="cvssboard", style="none"), 
        
        P(Br()),
        P(Strong("Severity")), Select(Option("Critical", value="Critical", selected=False), Option("High", value="High", selected=True), Option("Medium", value="Medium", selected=False), Option("Low", value="Low", selected=False), Option("Info", value="Low", selected=False), name="severity", id="issue-severity", **kw),
        
        P(Br()),
        P(Strong("Technical details (Proof-of-concept)")),
        Textarea(id="editor-poc", name="poc"),
        
        P(Strong("Impact")),
        Textarea(id="editor-impact", name="impact"),
        
        P(Strong("Recommendation")),
        Textarea(id="editor-recommendation", name="recommendation"))

## edit issue
def edit_issue_input(**kw):
    isCritical = False 
    isHigh = False
    isMedium = False
    isLow = False
    isInfo = False

    severity = kw.get('severity')

    if severity == "Critical":
        isCritical = True
    if severity == "High":
        isHigh = True
    if severity == "Medium":
        isMedium = True
    if severity == "Low":
        isLow = True
    if severity == "Info":
        isInfo = True

    return (
        H2("Edit issue"),
        
        Hidden(id="issue-report-id", name="report_id", value=kw.get('report_id'), **kw),
        
        P(Strong("Title")),
        Input(id="issue-title", name="title", value=kw.get('title'), **kw),
        
        P(Br()),
        P(Strong("Description")),
        Textarea(id="editor-description", name="description"),
        
        P(Strong("CVSS Vector")), 
        Div(Hidden(id="issue-cvss", name="cvss", value=kw.get('cvss'), **kw),
            Hidden(id="issue-score", name="score", value=kw.get('score'), **kw), id="cvssboard", style="none"),

        P(Br()),    
        P(Strong("Severity")), Select(Option("Critical", value="Critical", selected=isCritical), Option("High", value="High", selected=isHigh), Option("Medium", value="Medium", selected=isMedium), Option("Low", value="Low", selected=isLow), Option("Info", value="Info", selected=isInfo), name="severity", id="issue-severity", **kw),
        
        P(Br()),
        P(Strong("Technical details (Proof-of-concept)")),
        Textarea(id="editor-poc", name="poc"),
        
        P(Strong("Impact")),
        Textarea(id="editor-impact", name="impact"),
        
        P(Strong("Recommendation")),
        Textarea(id="editor-recommendation", name="recommendation"))

# navbar
nav = Nav(
        Ul(Li((Strong("Atri Reports 💨", onclick="window.location.href='/'")))),
        Ul(Li(A("Home", href="/")), Li(A("Reports", href="/reports")), Li(A("Vulnerabilities", href="/vulns")), Li(A("Templates", href="/templates")), Li(A("Docs", href="/docs")), Li(A("Logout", href="/logout", cls="contrast")))
)

# admin user creation
try:
    admin_user = users["atri"]

except NotFoundError:
    # if admin user is not created
    # create admin user with random password
    admin_username = "atri"
    admin_password = secrets.token_urlsafe(32)

    # hash password
    admin_password_bytes = admin_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = (bcrypt.hashpw(admin_password_bytes, salt)).decode('utf-8')

    # insert to the database
    users.insert(User(0, admin_username, hashed_password, "Admin", True))

    print(f'Log in with the following credentials:\nUSER: {admin_username}\nPASSWORD: {admin_password}')

# login page
@rt("/login")
async def get():
    title = 'Sign in'

    login_form = Form(
        Input(id='login', placeholder='Login'),
        Input(id='password', type='password', placeholder='Password'),
        Button('Login', type='submit'),
        action='/login', method='post')

    return (
        Title(title),
        Main(
            Div(
                H1(title),
                login_form, 
            cls='login-container'),
            cls='login-body'))

@rt("/login")
async def post(login:str, password:str, sess):

    # if login parameters not specified redirect to login
    if not login or not password:
        add_toast(sess, f"Invalid request parameters.", "error")
        return login_redir

    # get user by username
    try: 
        u = users[login]

    # if user not found return to login
    except NotFoundError:
        add_toast(sess, f"Incorrect user or password.", "error")
        return login_redir
    
    # check if password matches
    if not bcrypt.checkpw(password.encode('utf-8'), u.password.encode('utf-8')):
        add_toast(sess, f"Incorrect user or password.", "error")
        return login_redir
    
    # assign session
    sess['auth'] = u.login

    # if first login redirect to password change page
    if u.first_login == True:
        return RedirectResponse('/password-change', status_code=303)

    return RedirectResponse('/', status_code=303)

# logout endpoint
@rt("/logout")
async def get(sess):
    del sess['auth']
    return login_redir

# password change page
@rt("/password-change")
async def get(sess):

    # if user already changed password redirect to dashboard
    u = users[sess["auth"]]
    if not u.first_login:
        return RedirectResponse('/', status_code=303)

    title = 'Change your password'

    login_form = Form(
        Input(id='password', type='password', placeholder='New Password'),
        Input(id='password_repeat', type='password', placeholder='Repeat new password'),

        Button('Change password', type='submit'),
        action='/password-change', method='post')
    
    complexity_note = Div(
        H3("Password requirements:"),
        Ul(
            Li("At least 8 characters."),
            Li("At least one uppercase letter (A-Z)."),
            Li("At least one lowercase letter (a-z)."),
            Li("At least one number (0-9)."),
            Li("At least one special character (e.g., !@#$%^&*).")
        )
    )
    return (
        Title(title),
        Main(
            Div(
                H1(title),
                login_form,
                complexity_note, 
            cls='login-container'),
            cls='login-body'))

@rt("/password-change")
async def post(password:str, password_repeat:str, sess):
    if not password or not password_repeat:
        add_toast(sess, f"Invalid request parameters.", "error")
        return RedirectResponse('/password-change', status_code=303)

    if password != password_repeat:
        add_toast(sess, f"Passwords do not match.", "error")
        return RedirectResponse('/password-change', status_code=303)
    
    # check if the password is complex enough
    if password_complexity.validate(password):

        # get user from session
        u = users[sess["auth"]]

        # hash password
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = (bcrypt.hashpw(password_bytes, salt)).decode('utf-8')

        u.password = hashed_password
        u.first_login = False

        # update user entry
        users.upsert(u)

        return RedirectResponse('/', status_code=303)
    else:
        add_toast(sess, f"Password is not complex enough.", "error")
        return RedirectResponse('/password-change', status_code=303)

# main page
@rt("/")
async def get():
    title = 'Dashboard'

    latest_reports_table = []

    # get last 5 reports
    for report in reports()[-5:]:
        show = A(report.title, href=f'/reports/{report.id}', cls='contrast')
        latest_reports_table.append(Tr(Th(show), Td(report.client), Td(report.start_date), Td(report.authors)))

    # get issues count by severity
    issues_array = []
    issues_array.append(len((issues(where='severity = "Critical"'))))
    issues_array.append(len((issues(where='severity = "High"'))))
    issues_array.append(len((issues(where='severity = "Medium"'))))
    issues_array.append(len((issues(where='severity = "Low"'))))
    issues_array.append(len((issues(where='severity = "Info"'))))

    # get total issues count
    issues_count = sum(issues_array)

    # get report count
    report_count = len(reports())

    # get 

    return (
        Title(title),
        
        Main(nav, 
             H1(title),  
             
             Div(
                Div(
                    Article(
                        Strong("Recent reports"), Pre(),
                        Table(*latest_reports_table, id='report-list', cls='striped'))),

                Div(
                    Div(                        
                        Div(
                            
                            Div(Article(Strong("Reports created"), P(), P(report_count, cls="number-container"))),
                            Div(Article(Strong("Vulnerabilities reported"), P(), P(issues_count, cls="number-container")))),
                            Div(Article(Strong("Total vulnerabilities by severity"), P(), Canvas(id='severityChart')), cls='chart-container')
                        ,cls="grid main-page")),
                
                cls="grid"),
            cls='container'),
            Hidden(id='issue-array', value=issues_array),

            Script(src="https://cdn.jsdelivr.net/npm/chart.js"),
            Script(src="/assets/javascript/chart-helper.js"),
            Script("var issue_array = (document.getElementById('issue-array').value).split(' ').map(num => parseInt(num, 10)); createChart(issue_array);"))
    
# /reports
@rt("/reports")
async def get():
    title = "Reports"
        
    return (
        Title(title),  
        
        Main(nav, 
            H1(title), 
            
            A("Add new report", href="/reports/add", role="button"), Pre(),

            Article(
            Table(Tr(Th(Strong("Title")), Th(Strong("Client")), Th(Strong("Date")), Th(Strong("Author")), Th(),Th(),Th()), *reports(), id='report-table', cls="striped")),

        cls='container'))

@rt("/reports")
async def post(report:Report): 
    reports.insert(report)
    
    return Script(f"window.location.href='/reports'") 

@rt("/reports")
async def put(report: Report): 
    reports.upsert(report)
    
    return Script(f"window.location.href='/reports/{str(report.id)}'")

@rt("/reports/add")
async def get():
    editor = Form(H1("Add report sections"), Div(Button("Add")),  Pre(), new_report_input(), hx_post="/reports",)
    
    return Title("Add report sections"), Main(nav, editor, cls='container')

# report generation handler
@rt("/reports/generate/{id}/{template_id}")
async def get(id:int, template_id:int):

    # hex color enum for severity coloring
    class Color(Enum):
        Critical = "000000"
        High = "ff0200"
        Medium = "f49546"
        Low = "ffff00"
        Info = "caeeff"

    # get report from database
    context = {}
    context["report"] = vars(reports.get(id))
    context["vulnerabilities"] = []
    
    # get issues for this report and sort by cvss score
    for i in issues(where=f'report_id = {id}', order_by='score DESC'):
        context["vulnerabilities"].append(vars(i))
    
    context["report"]["critical_issue_count"] = 0
    context["report"]["high_issue_count"] = 0
    context["report"]["medium_issue_count"] = 0
    context["report"]["low_issue_count"] = 0
    context["report"]["info_issue_count"] = 0

    # select report template
    template_file = ""
    template_index = template_id - 1

    # get all report templates from the templates directory based on regex
    report_templates = []
    report_templates_path = './reports/templates/'
    report_templates_pattern = r'^(?!~\$).+\.docx$'
    report_template_files = [f for f in os.listdir(report_templates_path) if re.match(report_templates_pattern, f)]
    
    # create full template file path from file list and index
    template_file = report_templates_path + report_template_files[template_index]

    output_file = "reports/output/output.docx"
    template = DocxTemplate(template_file)

    images = {}

    context["report"]["summary"] = parseContext(context["report"]["summary"], images)
    context["report"]["scope"] = parseContext(context["report"]["scope"], images)

    for issue in context["vulnerabilities"]:
        issue["description"] = parseContext(issue["description"], images)
        issue["poc"] = parseContext(issue["poc"], images)
        issue["impact"] = parseContext(issue["impact"], images)
        issue["recommendation"] = parseContext(issue["recommendation"], images)
        
        match issue["severity"]:
            case "Critical":
                issue["color"] = Color.Critical.value
                issue["title_plain"] = issue["title"]
                issue["title"] = RichText(issue["title"], color="ffffff")
                issue["severity_plain"] = issue["severity"]
                issue["severity"] = RichText(f'[{issue["severity"]}]', color="ffffff")
                context["report"]["critical_issue_count"] += 1
            case "High":
                issue["color"] = Color.High.value
                issue["title_plain"] = issue["title"]
                issue["title"] = RichText(issue["title"], color="ffffff")
                issue["severity_plain"] = issue["severity"]
                issue["severity"] = RichText(f'[{issue["severity"]}]', color="ffffff")
                context["report"]["high_issue_count"] += 1
            case "Medium":
                issue["color"] = Color.Medium.value
                issue["title_plain"] = issue["title"]
                issue["title"] = RichText(issue["title"], color="ffffff")
                issue["severity_plain"] = issue["severity"]
                issue["severity"] = RichText(f'[{issue["severity"]}]', color="ffffff")
                context["report"]["medium_issue_count"] += 1
            case "Low":
                issue["color"] = Color.Low.value
                issue["title_plain"] = issue["title"]
                issue["title"] = RichText(issue["title"], color="000000")
                issue["severity_plain"] = issue["severity"]
                issue["severity"] = RichText(f'[{issue["severity"]}]', color="000000")
                context["report"]["low_issue_count"] += 1
            case "Info":
                issue["color"] = Color.Info.value
                issue["title_plain"] = issue["title"]
                issue["title"] = RichText(issue["title"], color="000000")
                issue["severity_plain"] = issue["severity"]
                issue["severity"] = RichText(f'[{issue["severity"]}]', color="000000")
                context["report"]["info_issue_count"] += 1
            case _:
                issue["color"] = Color.Info.value
                issue["title_plain"] = issue["title"]
                issue["title"] = RichText(issue["title"], color="000000")
                issue["severity_plain"] = issue["severity"]
                issue["severity"] = RichText(f'[{issue["severity"]}]', color="000000")
                context["report"]["info_issue_count"] += 1

    # sum all issues
    context["report"]["issue_count"] = context["report"]["critical_issue_count"] + context["report"]["high_issue_count"] + context["report"]["medium_issue_count"] + context["report"]["low_issue_count"]
    
    # generate issue chart
    categories = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    values = [context["report"]["info_issue_count"], context["report"]["low_issue_count"], context["report"]["medium_issue_count"], context["report"]["high_issue_count"], context["report"]["critical_issue_count"]]

    colors = ["#" + Color.Info.value, "#" + Color.Low.value, "#" + Color.Medium.value, "#" + Color.High.value, "#" + Color.Critical.value]

    fig, ax = plt.subplots()

    # create horizontal chart
    ax.barh(categories, values, color=colors)
    # with integers on X axis
    plt.gca().xaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    gray_color = '#7f7f7f'
    white_color = '#ffffff'

    # change axis colors
    ax.spines['left'].set_color(gray_color)
    ax.spines['bottom'].set_color(gray_color)
    ax.spines['right'].set_color(white_color)
    ax.spines['top'].set_color(white_color)

    # set labels colors
    ax.tick_params(axis='x', colors=gray_color)
    ax.tick_params(axis='y', colors=gray_color)

    # save the chart as image
    chart_path = "reports/output/plot.png"
    plt.savefig(chart_path)
    
    context["report"]["issue_chart"] = InlineImage(template, image_descriptor=chart_path, width=Mm(130))

    # render first without images
    template.render(context)
    template.save(output_file)

    template = DocxTemplate(output_file)

    context_images = {}

    # add images to template
    for image in images:
        img_path = images[image]
        context_images[image] = InlineImage(template, image_descriptor=img_path, width=Mm(160))

    # generate second time with images
    template.render(context_images)
    template.save(output_file)

    return FileResponse(output_file, filename="report.docx")

@rt("/reports/{id}")
async def get(id:int):
    report = reports.get(id)
    title = report.title
    client = report.client
    start_date = report.start_date
    end_date = report.end_date
    retest_date = report.retest_date
    authors = report.authors
    summary = report.summary
    scope = report.scope

    # get all report templates from the templates directory based on regex
    report_templates = []
    report_templates_path = './reports/templates/'
    report_templates_pattern = r'^(?!~\$).+\.docx$'
    report_template_files = [f for f in os.listdir(report_templates_path) if re.match(report_templates_pattern, f)]

    # create list of report template files
    for file in report_template_files:
        report_templates.append(file.split('.')[0])

    generate_button = Details(Summary('Generate', role="button", cls='secondary', id='generate-dropdown'), Ul(*[Li(A(template, href=f'/reports/generate/{report.id}/{report_templates.index(template) + 1}')) for template in report_templates]), cls='dropdown', style='float: right;')
    
    return (
        Title("Report - " + report.title), 
        
        Main(nav,
            H1("Report - " + report.title),
            
            Div(
                Div(
                    A("Add new issue", href='/issues/add/' + str(report.id), role="button"),
                    A("Add new issue from template", href='/issues/template/add/' + str(report.id), role="button"),
                    A("Edit report sections", href='/reports/edit/' + str(report.id), role="button"),
                    A("Duplicate", href='/reports/duplicate/' + str(report.id), role="button"),
                    A('Delete', hx_delete=f'/reports/{report.id}', hx_confirm='Do you really want to delete this report?', cls='contrast', role="button", hx_swap="outerhtml")),
                Div(generate_button), cls='grid'), Pre(),
                                                 
            Article(
            H3("Report sections"),
            
            Div(
                Div(
                    Strong("Title"),
                    P(title),), 
                Div(
                    Strong("Client"),
                    P(client)), 
                Div(
                    Strong("Authors"),
                    P(authors)), 
                cls="grid"),
            
            Div(
                Div(Strong("Start date"), P(start_date)), 
                Div(Strong("End date"), P(end_date)), 
                Div(Strong("Retest date"), P(retest_date), 
            ), cls="grid")), 
            
            Article(
            H3("Summary"),
            P(summary,cls="marked")), 
            
            Article(
            H3("Scope"),
            P(scope,cls="marked")), 

            Article(
                H3("Vulnerabilities"),
                Ul(*issues(where=f'report_id = {report.id}', order_by='score DESC'), id='issue-list', hx_swap="beforeend")), 
            
            cls='container'))

@rt("/reports/{id}")
async def delete(id:int):

    # remove all issues for the report
    for issue in issues(where=f'report_id = {id}'):
        issues.delete(issue.id)

    # remove report
    reports.delete(id)

    return "Delete", Script("window.location.href='/reports'")

@rt("/reports/edit/{id}")
async def get(id:int):
    report = reports.get(id)
    id = report.id
    title = report.title
    client = report.client
    start_date = report.start_date
    end_date = report.end_date
    retest_date = report.retest_date
    authors = report.authors
    summary_b64 = (base64.b64encode((report.summary).encode("utf-8"))).decode("utf-8")
    scope_b64 = (base64.b64encode((report.scope).encode("utf-8"))).decode("utf-8")

    editor = Form(H1("Edit report sections"), Div(Button("Save")),  Pre(), reports_attributes_input(id=id, title=title, start_date=start_date, end_date=end_date, retest_date=retest_date, client=client, authors=authors), hx_put="/reports",)
    
    return (
        Title("Editor - " + title),
        
        Main(nav, editor, cls='container'),
        
        Script(src="/assets/javascript/simplemde.min.js"),
        Script(src="/assets/javascript/base64-utf8.js"),
        Link(rel='stylesheet', href='/assets/css/simplemde.min.css', type='text/css'),
        
        Script('var summaryEditor = new SimpleMDE({ element: document.getElementById("editor-summary") });summaryEditor.value(b64DecodeUnicode("' + summary_b64 + '")); var scopeEditor = new SimpleMDE({ element: document.getElementById("editor-scope") });scopeEditor.value(b64DecodeUnicode("' + scope_b64 + '"));var editors = [summaryEditor,scopeEditor]'), 
        Script(src="/assets/javascript/clipboard-helper.js"))

@rt("/reports/duplicate/{id}")
async def get(id:int):
    duplicated_report = reports.get(id)
    new_report = Report(UNSET, duplicated_report.title, duplicated_report.client, duplicated_report.start_date, duplicated_report.end_date, duplicated_report.retest_date, duplicated_report.authors, duplicated_report.summary, duplicated_report.scope)
    
    # insert new report
    new_report_id = (reports.insert(new_report)).id
    
    # for each issue in duplicated report
    for issue in issues(where=f'report_id = {id}'):
        # create duplicated issue
        new_issue = Issue(UNSET, new_report_id, issue.title, issue.cvss, issue.score, issue.severity, issue.description, issue.poc, issue.impact, issue.recommendation)
        # insert issue
        issues.insert(new_issue)

    return "Duplicate", Script("window.location.href='/reports'")

# image handlers
@rt("/reports/images/upload")
async def post(file:str):
    id = uuid.uuid4()
    filepath = f'./reports/images/{id}.png'
    
    contents = await file.read()

    with open(filepath, "wb") as file:
        file.write(contents)

    return id

@rt("/reports/images/{uuid}")
async def get(uuid:str):
    
    filepath = f'./reports/images/{uuid}.png'

    return FileResponse(filepath)

# /issues
@rt("/issues/edit/{id}")
async def get(id:int):
    issue = issues.get(id)
    report_id = issue.report_id
    title = issue.title
    cvss = issue.cvss
    score = issue.score
    severity = issue.severity
    description_b64 = (base64.b64encode((issue.description).encode("utf-8"))).decode("utf-8")
    poc_b64 = (base64.b64encode((issue.poc).encode("utf-8"))).decode("utf-8")
    impact_b64 = (base64.b64encode((issue.impact).encode("utf-8"))).decode("utf-8")
    recommendation_b64 = (base64.b64encode((issue.recommendation).encode("utf-8"))).decode("utf-8")

    editor = Form(Group(Div(edit_issue_input(report_id=report_id, title=title, cvss=cvss, score=score, severity=severity)), Hidden(id="id", value=issue.id), Div(Button("Save"))), hx_put="/issues")

    return (
        Title("Edit issue"), 
        
        Main(nav, editor, cls='container'),
        
        # js and css for SimpleMDE editor
        Link(rel='stylesheet', href='/assets/css/simplemde.min.css', type='text/css'), 
        Script(src="/assets/javascript/simplemde.min.js"),
        Script(src="/assets/javascript/base64-utf8.js"),
        Script('var impactEditor = new SimpleMDE({ element: document.getElementById("editor-impact") });impactEditor.value(b64DecodeUnicode("' + impact_b64 + '")); var descriptionEditor = new SimpleMDE({ element: document.getElementById("editor-description") });descriptionEditor.value(b64DecodeUnicode("' + description_b64 + '"));var recommendationEditor = new SimpleMDE({ element: document.getElementById("editor-recommendation") });recommendationEditor.value(b64DecodeUnicode("' + recommendation_b64 + '"));var pocEditor = new SimpleMDE({ element: document.getElementById("editor-poc") });pocEditor.value(b64DecodeUnicode("' + poc_b64 + '"));var editors = [impactEditor,descriptionEditor,recommendationEditor,pocEditor]'), 
        
        # js handler for image pasting
        Script(src="/assets/javascript/clipboard-helper.js"),
        
        # js for cvssjs form
        Script(src="/assets/javascript/cvss.js"), 
        Script('var c = new CVSS("cvssboard", {onchange: function() {document.getElementById("issue-cvss").value = c.get().vector;document.getElementById("issue-score").value = c.get().score} });c.set(document.getElementById("issue-cvss").value);'))


@rt("/issues/add/{id}")
async def get(id:int):

    add = Form(Group(Div(new_issue_input(report_id=id)), Div(), Div(Button("Add"))), hx_post="/issues")
    
    return (
        Title("Add new issue"),
        
        Main(nav, add, cls='container'),
        
        Link(rel='stylesheet', href='/assets/css/simplemde.min.css', type='text/css'),
        Script(src="/assets/javascript/simplemde.min.js"),
        Script(src="/assets/javascript/base64-utf8.js"),
        Script('var impactEditor = new SimpleMDE({ element: document.getElementById("editor-impact") }); var descriptionEditor = new SimpleMDE({ element: document.getElementById("editor-description") });var recommendationEditor = new SimpleMDE({ element: document.getElementById("editor-recommendation") });var pocEditor = new SimpleMDE({ element: document.getElementById("editor-poc") });var editors = [impactEditor,descriptionEditor,recommendationEditor,pocEditor]'), 
        
        Script(src="/assets/javascript/clipboard-helper.js"),
        
        Script(src="/assets/javascript/cvss.js"),
        Script('var c = new CVSS("cvssboard", {onchange: function() {document.getElementById("issue-cvss").value = c.get().vector;document.getElementById("issue-score").value = c.get().score} })'))

@rt("/issues/template/add/{id}")
async def get(id:int):

    dropdown = Details(Summary('Select vulnerability'), Ul(*[Li(A(template.title, href=f'/issues/template/{id}/{template.id}')) for template in vulns()]), cls='dropdown')
    
    return Title("Select vulnerability to add"), Main(nav, H2("Select vulnerability to add"), dropdown, cls='container')

@rt("/issues/template/{id}/{template_id}")
async def get(id:int, template_id:int):

    template = vulns.get(template_id)
    report_id = id
    title = template.title
    cvss = template.cvss
    severity = template.severity
    description_b64 = (base64.b64encode((template.description).encode("utf-8"))).decode("utf-8")
    poc_b64 = (base64.b64encode((template.poc).encode("utf-8"))).decode("utf-8")
    impact_b64 = (base64.b64encode((template.impact).encode("utf-8"))).decode("utf-8")
    recommendation_b64 = (base64.b64encode((template.recommendation).encode("utf-8"))).decode("utf-8")

    editor = Form(Group(Div(edit_issue_input(report_id=report_id, title=title, cvss=cvss, severity=severity)), Div(), Div(Button("Save"))), hx_post="/issues")

    return (
        Title("Add new issue"),
        
        Main(nav, editor, cls='container'),
        
        Link(rel='stylesheet', href='/assets/css/simplemde.min.css', type='text/css'),
        Script(src="/assets/javascript/simplemde.min.js"),
        Script(src="/assets/javascript/base64-utf8.js"),
        Script('var impactEditor = new SimpleMDE({ element: document.getElementById("editor-impact") }); var descriptionEditor = new SimpleMDE({ element: document.getElementById("editor-description") });var recommendationEditor = new SimpleMDE({ element: document.getElementById("editor-recommendation") });var pocEditor = new SimpleMDE({ element: document.getElementById("editor-poc") });var editors = [impactEditor,descriptionEditor,recommendationEditor,pocEditor];impactEditor.value(b64DecodeUnicode("' + impact_b64 + '"));descriptionEditor.value(b64DecodeUnicode("' + description_b64 + '"));recommendationEditor.value(b64DecodeUnicode("' + recommendation_b64 + '"));pocEditor.value(b64DecodeUnicode("' + poc_b64 + '"));'),
        Script(src="/assets/javascript/clipboard-helper.js"),
        
        Script(src="/assets/javascript/cvss.js"),
        Script('var c = new CVSS("cvssboard", {onchange: function() {document.getElementById("issue-cvss").value = c.get().vector;document.getElementById("issue-score").value = c.get().score} });c.set(document.getElementById("issue-cvss").value);'))

@rt("/issues")
async def post(issue: Issue):
    issues.insert(issue)
    
    return Script(f"window.location.href='/reports/{issue.report_id}'")

@rt("/issues/{id}")
async def delete(id:int):
    issue = issues.get(id)
    report_id = issue.report_id

    issues.delete(id)

    return Script(f"window.location.href='/reports/{report_id}'")

@rt("/issues")
async def put(issue: Issue): 
    issues.upsert(issue)

    return Script(f"window.location.href='/reports/{issue.report_id}'")

# /vulns
@rt("/vulns")
async def get():
    title = 'Vulnerability base'

    return (
        Title(title),
        Main(nav, H1(title), 
             
            Div(
            
                Div(Input(id="vuln-search-box", type="search", placeholder="Search for templates...")),                
                Div(
                    A("New vulnerability template", href="/vulns/add", role="button"),
                    A("Import templates", href="/vulns/import", role="button"),
                    A("Delete all templates", role="button", hx_delete='/vulns/all', hx_confirm='Do you really want to delete all vulnerability templates?', cls='contrast')), 
            cls="grid"),

            Ul(*vulns(), id='vuln-list'),
        
        cls='container'), 
                
        Script(src='/assets/javascript/vuln-search.js'))

@rt("/vulns")
async def post(vuln:Vuln): 
    vulns.insert(vuln)

    return Script(f"window.location.href='/vulns'")

@rt("/vulns/all")
async def delete():
    for vuln in vulns():
        vulns.delete(vuln.id)
    
    return Script(f"window.location.href='/vulns'")

@rt("/vulns/{id}")
async def delete(id:int):
    vulns.delete(id)
    
    return Script(f"window.location.href='/vulns'")

@rt("/vulns")
async def put(vuln: Vuln): 
    vulns.upsert(vuln)
    
    return Script(f"window.location.href='/vulns'")

@rt("/vulns/add")
async def get():
    title = 'Add vulnerability template'

    add = Form(Group(Div(new_vuln_input()), Div(Button("Add"))), hx_post="/vulns")

    return (
        Title(title),  
        
        Main(nav, add, cls='container'),
        
        # js and css for SimpleMDE editor
        Link(rel='stylesheet', href='/assets/css/simplemde.min.css', type='text/css'),
        Script(src="/assets/javascript/simplemde.min.js"),
        Script(src="/assets/javascript/base64-utf8.js"),
        Script('var impactEditor = new SimpleMDE({ element: document.getElementById("editor-impact") }); var descriptionEditor = new SimpleMDE({ element: document.getElementById("editor-description") });var recommendationEditor = new SimpleMDE({ element: document.getElementById("editor-recommendation") });var pocEditor = new SimpleMDE({ element: document.getElementById("editor-poc") });var editors = [impactEditor,descriptionEditor,recommendationEditor,pocEditor]'),

        # js for cvssjs form
        Script(src="/assets/javascript/cvss.js"), 
        Script('var c = new CVSS("cvssboard", {onchange: function() {document.getElementById("issue-cvss").value = c.get().vector;document.getElementById("issue-score").value = c.get().score} });c.set(document.getElementById("issue-cvss").value);')) 
    

@rt("/vulns/edit/{id}")
async def get(id:int):
    title = 'Edit vulnerability template'

    vuln = vulns.get(id)
    title = vuln.title
    cvss = vuln.cvss
    score = vuln.score
    severity = vuln.severity
    description_b64 = (base64.b64encode((vuln.description).encode("utf-8"))).decode("utf-8")
    poc_b64 = (base64.b64encode((vuln.poc).encode("utf-8"))).decode("utf-8")
    impact_b64 = (base64.b64encode((vuln.impact).encode("utf-8"))).decode("utf-8")
    recommendation_b64 = (base64.b64encode((vuln.recommendation).encode("utf-8"))).decode("utf-8")

    edit = Form(Group(Div(edit_vuln_input(title=title, cvss=cvss, score=score, severity=severity)), Hidden(id="id", value=vuln.id), Div(Button("Save"))), hx_put="/vulns")

    return (
        Title(title),  
        
        Main(nav, edit, cls='container'),
        
        # js and css for SimpleMDE editor
        Link(rel='stylesheet', href='/assets/css/simplemde.min.css', type='text/css'),
        Script(src="/assets/javascript/simplemde.min.js"),
        Script(src="/assets/javascript/base64-utf8.js"),

        Script('var impactEditor = new SimpleMDE({ element: document.getElementById("editor-impact") }); var descriptionEditor = new SimpleMDE({ element: document.getElementById("editor-description") });var recommendationEditor = new SimpleMDE({ element: document.getElementById("editor-recommendation") });var pocEditor = new SimpleMDE({ element: document.getElementById("editor-poc") });var editors = [impactEditor,descriptionEditor,recommendationEditor,pocEditor]; impactEditor.value(b64DecodeUnicode("' + impact_b64 + '"));descriptionEditor.value(b64DecodeUnicode("' + description_b64 + '"));recommendationEditor.value(b64DecodeUnicode("' + recommendation_b64 + '"));pocEditor.value(b64DecodeUnicode("' + poc_b64 + '"));'),

        # js for cvssjs form
        Script(src="/assets/javascript/cvss.js"), 
        Script('var c = new CVSS("cvssboard", {onchange: function() {document.getElementById("issue-cvss").value = c.get().vector;document.getElementById("issue-score").value = c.get().score} });c.set(document.getElementById("issue-cvss").value);'))

@rt("/vulns/import")
async def get():
    title = 'Import templates'

    template_upload_form = Form(
        Article(Div(Input(type='file', id='file', name='file', accept='.csv')), cls='file-upload-area'),
        Div(Button("Import templates"), cls='grid'), 
        enctype="multipart/form-data", hx_post="/vulns/import")
        
    
    return (
        Title(title),
        Main(nav, H1(title),
            Article(
            Div(P(Strong("Upload or drop file with vulnerability templates:"))),
            Div(template_upload_form),
            Br(),
            P("Only CSV files are accepted. Ensure that uploaded file matches the template:"),
            A("Download sample template", href="/vulns/import/template", role="button", cls='secondary')
            )
        ,cls='container'))

@rt("/vulns/import/template")
async def get():
    template_file = f'./assets/templates/vulnerability_import_template.csv'
    
    return FileResponse(template_file)

# vulnerability template bulk import handler
@rt("/vulns/import")
async def post(file:str):
    vulns_to_be_imported = []

    # read contents of csv file and decode to readable format
    contents = await file.read()
    csv_file = io.BytesIO(contents)
    csv_text = io.TextIOWrapper(csv_file, encoding='utf-8')
    
    # read each row
    csv_reader = csv.DictReader(csv_text)
    for row in csv_reader:
        vuln = {
            "title":row['title'],
            "cvss":row['cvss'],
            "severity":row['severity'],
            "description":row['description'],
            "poc":row['poc'],
            "impact":row['impact'],
            "recommendation":row['recommendation']
        }
        # add vuln to array
        vulns_to_be_imported.append(vuln)

    # add vulns to the database
    for vuln in vulns_to_be_imported:
        vulns.insert(vuln)

    return Script(f"window.location.href='/vulns'")

# /templates
@rt("/templates")
async def get():
    title = "Report templates"

    # get all report templates from the templates directory based on regex
    report_templates = []
    report_templates_path = './reports/templates/'
    report_templates_pattern = r'^(?!~\$).+\.docx$'
    report_template_files = [f for f in os.listdir(report_templates_path) if re.match(report_templates_pattern, f)]

    # add templates to list
    for file in report_template_files:
        report_templates.append(file)

    report_templates_table = []

    # create table from listed templates
    for template in report_templates:
        template_name = template.split(".docx")[0]
        description = "Sample description"
        upload_date = time.ctime(os.path.getctime(report_templates_path + template))
        creator = "Admin"
        download = A(Img(src='/assets/icons/download.svg', cls="icon"), href=f'/templates/{template_name}', data_tooltip='Download')
        delete = A(Img(src='/assets/icons/delete.svg', cls="icon-delete"), hx_delete=f'/templates/{template_name}', hx_confirm='Do you really want to delete this template?', data_tooltip='Delete')
        
        report_templates_table.append(Tr(Th(template_name), Td(description), Td(upload_date), Td(creator), Td(download), Td(delete)))

    return (
        Title(title),  
        
        Main(nav, 
            H1(title), 
            
            A("Add new report template", href="/templates/add", role="button"), Pre(),

            Article(
            Table(Tr(Th(Strong("Template name")), Th(Strong("Description")), Th(Strong("Upload date")), Th(Strong("Creator")), Th(),Th()), *report_templates_table, id='report-table', cls="striped")),

        cls='container'))

# upload report template
@rt("/templates")
async def post(file:str):
    # get file name and set file path
    filename = (file.filename).split('.')[0]

    pattern = r'^[a-zA-Z0-9._-]+$'
    
    # use the regex to check filename for invalid characters
    if not re.match(pattern, filename):
        return "Invalid filename"

    filepath = f'./reports/templates/{filename}.docx'
    
    contents = await file.read()

    with open(filepath, "wb") as file:
        file.write(contents)

    return "Upload", Script("window.location.href='/templates'")


@rt("/templates/add")
async def get():
    title = 'Upload report template'

    template_upload_form = Form(
        Article(Div(Input(type='file', id='file', name='file', accept='.docx')), cls='file-upload-area'),
        Div(Button("Upload"), cls='grid'), 
        enctype="multipart/form-data", hx_post="/templates")
        
    
    return (
        Title(title),
        Main(nav, H1(title),
            Article(
            Div(P(Strong("Upload or drop a report template:"))),
            Div(template_upload_form),
            Br(),
            P("Only DOCX files are accepted. Ensure that uploaded file matches the template:"),
            A("Download sample template", href="/templates/default", role="button", cls='secondary')
            )
        ,cls='container'))

@rt("/templates/{file}")
async def get(file:str):
    
    # get report template files
    report_templates = []
    report_templates_path = './reports/templates/'
    report_templates_pattern = r'^(?!~\$).+\.docx$'
    report_template_files = [f for f in os.listdir(report_templates_path) if re.match(report_templates_pattern, f)]

    # check if template is in the directory
    if f'{file}.docx' not in report_template_files:
        return "Template not found."
    
    else:
        filepath = f'{report_templates_path}{file}.docx'
        # do not cache template file in browser
        return FileResponse(filepath, headers={'Cache-Control':'no-store, no-cache, must-revalidate, max-age=0'})

@rt("/templates/{file}")
async def delete(file:str):
    
    # get report template files
    report_templates = []
    report_templates_path = './reports/templates/'
    report_templates_pattern = r'^(?!~\$).+\.docx$'
    report_template_files = [f for f in os.listdir(report_templates_path) if re.match(report_templates_pattern, f)]

    # check if template is in the directory
    if f'{file}.docx' not in report_template_files:
        return "Template not found."
    
    else:
        filepath = f'{report_templates_path}{file}.docx'
        os.remove(filepath)
        return "Delete", Script("window.location.href='/templates'")

@rt("/docs")
async def get():
    # read the contents of DOCS.md
    docs_path = './DOCS.md'
    try:
        with open(docs_path, 'r', encoding='utf-8') as file:
            docs_content = file.read()
    except FileNotFoundError:
        docs_content = "DOCS.md file not found."

    title = "Documentation"

    return (
        Title(title),
        Main(nav, 
             H1(title), 
             Article(P(docs_content, cls="marked")), 
             cls='container'))

# run the application
serve()