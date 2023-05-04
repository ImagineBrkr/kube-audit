import json
import pandas as pd
import plotly.graph_objs as go
import dash
from dash import dcc
from dash import html
from dash.dependencies import Input, Output
import plotly.express as px
from dash import dash_table

file_kube_audit = "2023-05-03T12_57_48_output_kube_audit.json"
file_kube_linter = "2023-05-03T12_57_48_output_kube_linter.json"
file_terrascan = "2023-05-03T12_57_48_output_terrascan.json"
file_trivy = "2023-05-03T12_57_48_output_trivy.json"

app = dash.Dash(__name__)
app.layout = html.Div(
    [html.H1("Auditoría de Kubernetes"),
    html.Div(
            [html.Div(
                [html.H3("Resultados de Trivy"),
                dcc.Dropdown(
                    id="group_by_dropdown_trivy",
                    options=[
                        {"label": "Category", "value": "Category"},
                        {"label": "Severity", "value": "Severity"},
                        {"label": "RuleID", "value": "RuleID"},
                    ],
                    value="Category",
                ),
                dcc.Graph(id="bar_chart_trivy"),
                ], className="six columns"),
            html.Div(
                    [html.H3("Resultados de Kube Audit"),
                    dcc.Dropdown(
                        id="group_by_dropdown_kube_audit",
                        options=[{"label": "Opción 1", "value": "option1"},
                                     {"label": "Opción 2", "value": "option2"}],
                        value="option1",
                    ),
                    dcc.Graph(id="bar_chart_kube_audit"),
                    ], className="six columns",),
            ],
            className="row",),
    html.Div(
            [html.Div(
                    [html.H3("Resultados de Kube Linter"),
                    dcc.Dropdown(
                    id="group_by_dropdown_kube_linter",
                    options=[
                        {"label": "Checks", "value": "Checks"},
                        {"label": "Reports", "value": "Reports"},
                    ],
                    value="Checks",
                    ),
                    dash_table.DataTable(
                        id="details_table_kube_linter",
                        columns=[],
                        data=[],
                        page_size=10,
                        style_table={"overflowX": "auto"},
                        style_header= {'whiteSpace':'normal'},
                        style_data={
                            'whiteSpace': 'normal',
                            'height': 'auto',
                        },
                        style_cell={'textAlign': 'left'},
                    ),
                    ], className="six columns",),
            html.Div(
                    [html.H3("Resultados de Terrascan"),
                    dcc.Dropdown(
                        id="group_by_dropdown_terrascan",
                        options=[{"label": "Opción 1", "value": "option1"},
                                     {"label": "Opción 2", "value": "option2"}],
                        value="option1",
                    ),
                    dcc.Graph(id="bar_chart_terrascan"),
                    ], className="six columns",),
        ],className="row",),
    html.Div([
        html.Div(html.H2("Detalles"), className="row"),
        dash_table.DataTable(
            id="details_table",
            columns=[],
            data=[],
            page_size=10,
            style_table={"overflowX": "auto"},
        ),]),
    ]
)


def load_json_file(file_path):
    with open(file_path, encoding="utf-8-sig") as json_file:
        json_string = json_file.read()
        # json_string = json_file.read()
        data = json.loads(json_string)
    return data

def parse_trivy(data):
    results = data["Results"]
    # Aplanar la columna "Secrets"
    flattened_data = []
    for result in results:
        for secret in result['Secrets']:
            for line in secret['Code']['Lines']:
                flattened_data.append({
                    "Target": result["Target"],
                    "Class": result["Class"],
                    "RuleID": secret["RuleID"],
                    "Category": secret["Category"],
                    "Severity": secret["Severity"],
                    "Title": secret["Title"],
                    "LineNumber": line["Number"],
                    "IsCause": line["IsCause"],
                })

    df = pd.DataFrame(flattened_data)
    return df

def show_trivy():
    json_trivy = load_json_file(file_trivy)
    df = parse_trivy(json_trivy)

    # Crear una función de callback para actualizar el gráfico
    @app.callback(
        Output("bar_chart_trivy", "figure"),
        [Input("group_by_dropdown_trivy", "value")]
    )
    def update_chart(group_by):
        grouped_df = df.groupby(group_by).size().reset_index(name="Count")
        fig = px.bar(grouped_df, x=group_by, y="Count", hover_data=[group_by, "Count"])
        fig.update_layout(
            title=f"Número de ocurrencias por {group_by}",
            xaxis_title=group_by,
            yaxis_title="Count",
        )

        return fig
    
    @app.callback(
        [Output("details_table", "data"), Output("details_table", "columns")],
        Input("bar_chart_trivy", "clickData"),
        Input("group_by_dropdown_trivy", "value"),
    )
    def update_table(clickData, group_by):
        if clickData:
            selected_value = clickData["points"][0]["x"]
            filtered_df = df[df[group_by] == selected_value]
            columns = [{"name": i, "id": i} for i in df.columns]
        else:
            filtered_df = pd.DataFrame(columns=df.columns)
            columns = []

        return filtered_df.to_dict("records"), columns

def parse_kube_linter(data):
    # Aplanar la columna "Secrets"
    checks_df = pd.DataFrame(data["Checks"])
    checks_df["scope"] = checks_df["scope"].apply(json.dumps)
    checks_df["params"] = checks_df["params"].apply(json.dumps)

    reports_df = pd.DataFrame(data["Reports"])
    reports_df["Diagnostic"] = reports_df["Diagnostic"].apply(json.dumps)
    reports_df["Object"] = reports_df["Object"].apply(json.dumps)

    return checks_df, reports_df

def show_kube_linter():
    json_kube_linter = load_json_file(file_kube_linter)
    checks_df, reports_df = parse_kube_linter(json_kube_linter)
    @app.callback(
        [Output("details_table_kube_linter", "data"), Output("details_table_kube_linter", "columns")],
        [Input("group_by_dropdown_kube_linter", "value")]
    )
    def update_table(selection):
        if selection == "Checks":
            df = checks_df
        elif selection == "Reports":
            df = reports_df
        columns = [{"name": i, "id": i} for i in df.columns]
        return df.to_dict("records"), columns

def parse_kube_audit(data):
    
    df = pd.DataFrame(data)
    
    return df

def show_kube_audit():
    json_kube_audit = load_json_file(file_kube_audit)
    df = parse_kube_audit(json_kube_audit)
    print(df.head(10))




def show_terrascan():
    df1 = load_json_file(file_terrascan)





if __name__ == "__main__":
    show_trivy()
    show_kube_linter()
    show_kube_audit()
    app.run_server(debug=True)
