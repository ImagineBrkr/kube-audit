import json
import pandas as pd
import plotly.graph_objs as go
import dash
from dash import dcc
from dash import html
from dash.dependencies import Input, Output
import plotly.express as px
from dash import dash_table
import plotly.colors

file_kube_audit = "2023-05-03T12_57_48_output_kube_audit.json"
file_kube_linter = "2023-05-03T12_57_48_output_kube_linter.json"
file_terrascan = "2023-05-03T12_57_48_output_terrascan.json"
file_trivy = "2023-05-03T12_57_48_output_trivy.json"

def empty_styled_data_table(id):
    table = dash_table.DataTable(
        id = id,
        # Estilos de la tabla
        columns=[],
        data=[],
        style_data={
            'whiteSpace': 'normal',
            'height': 'auto',
        },
        style_table={
            'overflowX': 'auto'
        },
        style_cell={
            'textAlign': 'left',
            'font_family': 'Arial',
            'font_size': '14px',
            'padding': '5px',
        },
        style_header={
            'backgroundColor': '#f9f9f9',
            'fontWeight': 'bold',
            'border': '1px solid #e5e5e5',
            'whiteSpace': 'normal',
        },
        style_data_conditional=[
            {
                'if': {'row_index': 'odd'},
                'backgroundColor': 'white',
            },
            {
                'if': {'row_index': 'even'},
                'backgroundColor': '#f2f2f2',
            },
        ],
        style_cell_conditional=[
            {
                'if': {'column_id': c},
                'textAlign': 'left'
            } for c in ['Column1', 'Column2', 'Column3']
        ],
        sort_action="native",
        sort_mode="multi",
        filter_action="native",
        page_action="native",
        page_current=0,
        page_size=10,
    )

    return table

def add_style_graph(fig, title, x_label, y_label = "Total"):
    # Estilizar el gráfico
    fig.update_layout(
        title={
            'text': title,
            'y': 0.9,
            'x': 0.5,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {
                'size': 24,
                'family': 'Arial, sans-serif',
                'color': 'black'
            }
        },
        xaxis_title={
            'text': x_label,
            'font': {
                'size': 18,
                'family': 'Arial, sans-serif',
                'color': 'black'
            }
        },
        yaxis_title={
            'text': "Total",
            'font': {
                'size': 18,
                'family': 'Arial, sans-serif',
                'color': 'black'
            }
        },
        plot_bgcolor='rgba(0, 0, 0, 0)',  # Fondo transparente
        paper_bgcolor='rgba(0, 0, 0, 0)',  # Fondo transparente
    )
    # Usa una paleta de colores cualitativa de Plotly
    palette = plotly.colors.qualitative.Plotly
    # Estilizar las barras
    fig.update_traces(
        marker=dict(color=palette * 5, line= {'color': 'black', 'width':1.5})  # Repite la paleta si es necesario

        # {
        #     'color': 'blue',  # Color de las barras
        #     'line': {
        #         'color': 'black',  # Color del borde de las barras
        #         'width': 1.5  # Grosor del borde de las barras
        #     }
        # },
    )

    return fig

def add_style_table(table):
    table =dash_table.DataTable()    
    
# INITIAL LAYOUT

app = dash.Dash(__name__)
app.layout = html.Div(
    [html.H1("Auditoría de Microservicios"),
     html.Div(
        [html.Div(
            [html.H3("Resultados de Trivy"),
             dcc.Dropdown(
                id="group_by_dropdown_trivy",
                options=[],

            ),
                dcc.Graph(id="bar_chart_trivy"),
            ], className="six columns"),
         html.Div(
            [html.H3("Resultados de Kube Audit"),
             dcc.Dropdown(
                id="group_by_dropdown_kube_audit",
                options=[],

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
                empty_styled_data_table('details_table_kube_linter'),
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
         ], className="row",),
     html.Div([
         html.Div(html.H2("Detalles"), className="row"),
         empty_styled_data_table('details_table'),]),
     ]
)


def load_json_file(file_path):
    with open(file_path, encoding="utf-8-sig") as json_file:

        data = json.loads(json_file.read())
    return data


# PARSING JSON FILES

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


def parse_kube_audit(data):

    df = pd.DataFrame(data)

    return df


def parse_kube_linter(data):
    # Aplanar la columna "Secrets"
    checks_df = pd.DataFrame(data["Checks"])
    checks_df["scope"] = checks_df["scope"].apply(json.dumps)
    checks_df["params"] = checks_df["params"].apply(json.dumps)

    reports_df = pd.DataFrame(data["Reports"])
    reports_df["Diagnostic"] = reports_df["Diagnostic"].apply(json.dumps)
    reports_df["Object"] = reports_df["Object"].apply(json.dumps)

    return checks_df, reports_df


def parse_terrascan(data):
    df = pd.DataFrame(data["results"]["violations"])
    return df


# GRAPHICS FOR EACH TOOL

####TRIVY #####

def show_trivy():
    json_trivy = load_json_file(file_trivy)
    df = parse_trivy(json_trivy)
    options = [{"label": "Severidad", "value": "Severity"},
               {"label": "Categoría", "value": "Category"},
               {"label": "Regla", "value": "RuleID"}]

    @app.callback(
        Output("group_by_dropdown_trivy", "options"),
        Output("group_by_dropdown_trivy", "value"),
        Input("group_by_dropdown_trivy", "id")
    )
    def load_dropdown_options(id):
        return options, options[0]["value"]

    # Crear una función de callback para actualizar el gráfico
    @app.callback(
        Output("bar_chart_trivy", "figure"),
        [Input("group_by_dropdown_trivy", "value")]
    )
    def update_chart(group_by):
        #Buscar el Label
        label = next((option["label"] for option in options if option["value"] == group_by), None)
        grouped_df = df.groupby(group_by).size().reset_index(name="Count")
        fig = px.bar(grouped_df, x=group_by, y="Count",
                     hover_data=[group_by, "Count"])
        fig = add_style_graph(fig, f"Número de ocurrencias por {label}", label)

        return fig

    @app.callback(
        [Output("details_table", "data", allow_duplicate=True),
         Output("details_table", "columns", allow_duplicate=True)],
        Input("bar_chart_trivy", "clickData"),
        Input("group_by_dropdown_trivy", "value"),
        prevent_initial_call=True
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


#### KUBE LINTER #####

def show_kube_linter():
    json_kube_linter = load_json_file(file_kube_linter)
    checks_df, reports_df = parse_kube_linter(json_kube_linter)

    @app.callback(
        [Output("details_table_kube_linter", "data"),
         Output("details_table_kube_linter", "columns")],
        [Input("group_by_dropdown_kube_linter", "value")]
    )
    def update_table(selection):
        if selection == "Checks":
            df = checks_df
        elif selection == "Reports":
            df = reports_df
        columns = [{"name": i, "id": i} for i in df.columns]
        return df.to_dict("records"), columns


#### KUBE AUDIT #####

def show_kube_audit():
    json_kube_audit = load_json_file(file_kube_audit)
    df = parse_kube_audit(json_kube_audit)
    options = [{"label": "AuditResultName", "value": "AuditResultName"},
               {"label": "ResourceApiVersion", "value": "ResourceApiVersion"},
               {"label": "ResourceKind", "value": "ResourceKind"}]

    @app.callback(
        Output("group_by_dropdown_kube_audit", "options"),
        Output("group_by_dropdown_kube_audit", "value"),
        Input("group_by_dropdown_kube_audit", "id")
    )
    def load_dropdown_options(id):
        return options, options[0]["value"]

    # Crear una función de callback para actualizar el gráfico
    @app.callback(
        Output("bar_chart_kube_audit", "figure"),
        [Input("group_by_dropdown_kube_audit", "value")]
    )
    def update_chart(group_by):
        #Buscar el Label
        label = next((option["label"] for option in options if option["value"] == group_by), None)
        grouped_df = df.groupby(group_by).size().reset_index(name="Count")
        fig = px.bar(grouped_df, x=group_by, y="Count",
                     hover_data=[group_by, "Count"])
        fig.update_layout(
            title=f"Número de ocurrencias por {label}",
            xaxis_title=label,
            yaxis_title="Total",
        )
        fig = add_style_graph(fig, f"Número de ocurrencias por {label}", label)
        return fig

    @app.callback(
        [Output("details_table", "data", allow_duplicate=True),
         Output("details_table", "columns", allow_duplicate=True)],
        Input("bar_chart_kube_audit", "clickData"),
        Input("group_by_dropdown_kube_audit", "value"),
        prevent_initial_call=True
    )
    def update_table(clickData, group_by):
        if clickData:
            selected_value = clickData["points"][0]["x"]
            filtered_df = df[df[group_by] == selected_value]
            filtered_df = filtered_df.dropna(how='all', axis=1)
            columns = [{"name": i, "id": i} for i in filtered_df.columns]
        else:
            filtered_df = pd.DataFrame(columns=df.columns)
            columns = []

        return filtered_df.to_dict("records"), columns


#### TERRASCAN #####

def show_terrascan():
    json_terrascan = load_json_file(file_terrascan)
    df = parse_terrascan(json_terrascan)
    options = [{"label": "Severidad", "value": "severity"},
               {"label": "Categoría", "value": "category"},
               {"label": "Tipo de recurso", "value": "resource_type"}]
    
    @app.callback(
        Output("group_by_dropdown_terrascan", "options"),
        Output("group_by_dropdown_terrascan", "value"),
        Input("group_by_dropdown_terrascan", "id")
    )
    def load_dropdown_options(id):
        return options, options[0]["value"]

    # Crear una función de callback para actualizar el gráfico
    @app.callback(
        Output("bar_chart_terrascan", "figure"),
        [Input("group_by_dropdown_terrascan", "value")]
    )
    def update_chart(group_by):
        #Buscar el Label
        label = next((option["label"] for option in options if option["value"] == group_by), None)

        grouped_df = df.groupby(group_by).size().reset_index(name="Count")
        fig = px.bar(grouped_df, x=group_by, y="Count",
                     hover_data=[group_by, "Count"])
        fig.update_layout(
            title=f"Número de ocurrencias por {label}",
            xaxis_title=label,
            yaxis_title="Count",
        )
        fig = add_style_graph(fig, f"Número de ocurrencias por {label}", label)
        return fig

    @app.callback(
        [Output("details_table", "data", allow_duplicate=True),
         Output("details_table", "columns", allow_duplicate=True)],
        Input("bar_chart_terrascan", "clickData"),
        Input("group_by_dropdown_terrascan", "value"),
        prevent_initial_call=True
    )
    def update_table(clickData, group_by):
        if clickData:
            selected_value = clickData["points"][0]["x"]
            filtered_df = df[df[group_by] == selected_value]
            filtered_df = filtered_df.dropna(how='all', axis=1)
            columns = [{"name": i, "id": i} for i in filtered_df.columns]
        else:
            filtered_df = pd.DataFrame(columns=df.columns)
            columns = []

        return filtered_df.to_dict("records"), columns




if __name__ == "__main__":
    show_trivy()
    show_kube_linter()
    show_kube_audit()
    show_terrascan()
    app.run_server(debug=True)
