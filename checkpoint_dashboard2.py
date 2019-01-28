import dash
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go
import plotly.figure_factory as ff
import pandas as pd
from dash.dependencies import Input, Output
import os
from checkpoint_img import check_img
import numpy as np

DATA_PATH = '../Data'
df_benign = pd.read_csv(os.path.join(DATA_PATH, 'Train_Benign_Traffic.csv'), encoding='latin1')
df_detections = pd.read_csv(os.path.join(DATA_PATH, 'Train_Detections.csv'), encoding='latin1')
df_ips = pd.read_csv(os.path.join(DATA_PATH, 'Train_IPS.csv'), encoding='latin1')
df_set = pd.read_csv(os.path.join(DATA_PATH, 'Test_Set_Hackathon.csv'), encoding='latin1')
df_enrich = pd.read_csv(os.path.join(DATA_PATH, 'enrich_data_binary.csv'), encoding='latin1')

df_benign['label'] = 'Benign'
df_detections['label'] = 'Malicious'
full_data = pd.concat([df_benign, df_detections], axis=0, sort=False)

CHECKPOINT_IMG = check_img

external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
app.css.config.serve_locally = True
app.scripts.config.serve_locally = True
# app = dash.Dash()

available_clients = full_data['client'].unique()
available_clients = np.append(available_clients, ['All'])
app.layout = html.Div(
    [
        # header
        html.Div([

            html.Span("Dashboard Analysis", className='app-header--title', style={'fontSize':50, 'color':'white'}), 
            
            html.Div(
                html.Img(src=CHECKPOINT_IMG,height="100%")
                ,style={"float":"right","height":"100%"})
            ],
            className="row header",
            style={'background-color':'#0c0056'} 
            ),

        # Tab 1
        html.Div([
            # Dropdown
            html.Div([
                dcc.Dropdown(
                    id='client_dropdown',
                    options=[{'label': 'Client ' + str(i), 'value': i} for i in sorted(available_clients)],
                    placeholder='Select a client',
                    value = 1,
                    style={'fontSize':20}
                )],
                    style={'width': '49%', 'display': 'inline-block'})
                ],
                style={
                'borderBottom': 'thin lightgrey solid',
                'backgroundColor': 'rgb(250, 250, 250)',
                'padding': '10px 5px'}
                ),

        html.Div([
            # 1 Graph
            dcc.Graph(
                id='hist_protocols',
                )
                ], style={'width': '49%', 'display': 'inline-block', 'padding': '0 20'}),
        
        html.Div([
            # 2 Graph
            dcc.Graph(id='pie_port_b'),
            dcc.Graph(id='pie_port_m')
                ], style={'width': '49%', 'display': 'inline-block', 'padding': '0 20'}),
        
        html.Div([
            # Widget src
            html.Div([
                dcc.Dropdown(
                    id='type_source',
                    options=[{'label': i, 'value': i} for i in ['Internal', 'External']],
                    placeholder='Select Type Source',
                    value='Internal'
                ),
            ],
            style={'width': '49%', 'display': 'inline-block'}),
            # Widget dst
            html.Div([
                dcc.Dropdown(
                    id='type_destination',
                    options=[{'label': i, 'value': i} for i in ['Internal', 'External']],
                    placeholder='Select Type Destination',
                    value='Internal'
                ),
            ], style={'width': '49%', 'float': 'right', 'display': 'inline-block'})
        ], style={
            'borderBottom': 'thin lightgrey solid',
            'backgroundColor': 'rgb(250, 250, 250)',
            'padding': '10px 5px'
            }),
        
        html.Div([
            # 4 Graph: mean bytes by type  
            dcc.Graph(
                id='hist_types',
                )
                ], style={'width': '95%','display': 'inline-block', 'padding': '0 20'}),

        html.Div([
            # 5 Graph: distrib bytes received
            dcc.Graph(
                id='hist_bytes_received',
                )
                ], style={'width': '49%', 'display': 'inline-block', 'padding': '0 20'}),
        html.Div([
            # 6 Graph: distrib bytes sent
            dcc.Graph(
                id='hist_bytes_sent',
                )
                ], style={'width': '49%', 'display': 'inline-block', 'padding': '0 20'})  
            ])
        
# def get_df(df, clients):
#     if clients == 'All':
#         return df
#     else:
#         return df[df['client'] == int(clients)] 


@app.callback(
    Output(component_id='hist_protocols', component_property='figure'), 
    [Input(component_id='client_dropdown', component_property='value')]
    )
def update_graph(clients):
    if clients == 'All':
        sub_df = full_data
    else:
        sub_df = full_data[full_data['client'] == int(clients)]
    # sub_df = get_df(full_data, clients)
    ben_df = sub_df[sub_df['label'] == 'Benign']
    mal_df = sub_df[sub_df['label'] == 'Malicious']
    
    return {
        'data': [go.Histogram(
            x=ben_df.protocol,
            histnorm='percent',
            name = 'Benign',
            marker={'color':'#054194'},
            opacity=0.75
                )
                ,
                go.Histogram(
            x=mal_df.protocol,
            histnorm='percent',
            name = 'Malicious',
            marker={'color':'#f97cce'},
            opacity=0.75,
                )]
        ,
        'layout': go.Layout(
            title='<b>Protocols: Benign/Malicious</b>',
            xaxis={'title': 'Protocoles' },
            yaxis={'title': 'Count'},
            margin={'l': 70, 'b': 50, 't': 25, 'r': 0},
            height=700,
            bargap=0.2,
            bargroupgap=0.1
        )
            }
        

@app.callback(
    Output(component_id='pie_port_b', component_property='figure'), 
    [Input(component_id='client_dropdown', component_property='value')]
    )
def update_graph2(clients):
    # Pie
    if clients == 'All':
        sub_df = full_data
    else:
        sub_df = full_data[full_data['client'] == int(clients)]
    # sub_df = full_data[full_data['client'] == clients]
    # sub_df = get_df(full_data, clients)
    ben_df = sub_df[sub_df['label'] == 'Benign']
    mal_df = sub_df[sub_df['label'] == 'Malicious']
    labels = full_data['dst_port'].unique()
    return {
        'data': [
        go.Pie(
            hole=0.5,
            sort=False,
            direction='clockwise',
            domain={'x': [0.15, 0.85], 'y': [0.15, 0.85]},
            values=ben_df[ben_df['dst_port'] > 10]['dst_port'],
            labels = labels,
            textinfo='label',
            textposition='inside'
                    )
                ,
                ]
        ,
        'layout': go.Layout(
            title='<b>Destination Ports Benign</b>',
            margin={'l': 70, 'b': 20, 't': 50, 'r': 0},
            height=450
        )
            }

@app.callback(
    Output(component_id='pie_port_m', component_property='figure'), 
    [Input(component_id='client_dropdown', component_property='value')]
    )
def update_graph3(clients):
    # Pie
    if clients == 'All':
        sub_df = full_data
    else:
        sub_df = full_data[full_data['client'] == int(clients)]
    # sub_df = full_data[full_data['client'] == clients]
    # sub_df = get_df(full_data, clients)
    ben_df = sub_df[sub_df['label'] == 'Benign']
    mal_df = sub_df[sub_df['label'] == 'Malicious']
    labels = full_data['dst_port'].unique()
    
    return {
        'data': [
        go.Pie(
            hole=0.5,
            sort=False,
            direction='clockwise',
            domain={'x': [0.15, 0.85], 'y': [0.15, 0.85]},
            values=mal_df[mal_df['dst_port'] > 10]['dst_port'],
            textinfo='label',
            textposition='inside',
            labels = labels
                    )
                ,
                ]
        ,
        'layout': go.Layout(
            title='<b>Destination Ports Malicious</b>',
            margin={'l': 70, 'b': 20, 't': 50, 'r': 0},
            height=450
        )
            }


@app.callback(
    Output(component_id='hist_types', component_property='figure'), 
    [Input(component_id='client_dropdown', component_property='value'),
    Input(component_id='type_source', component_property='value'),
    Input(component_id='type_destination', component_property='value')]
    )
def update_graph4(clients, source, destination):
    if clients == 'All':
        sub_df = df_enrich[(df_enrich['type_src'] == source) & (df_enrich['type_dst'] == destination)]
    else:
        sub_df = df_enrich[(df_enrich['client'] == int(clients)) & (df_enrich['type_src'] == source) & (df_enrich['type_dst'] == destination)]
    # sub_df = df_enrich[(df_enrich['client'] == clients) & (df_enrich['type_src'] == source) & (df_enrich['type_dst'] == destination)]
    ben_df = sub_df[sub_df['label2'] == 'benign']
    mal_df = sub_df[sub_df['label2'] == 'malicious']
    
    return {
        'data': [go.Bar(
            x=['Received', 'Sent'],
            y = [ben_df.received_bytes.mean(), ben_df.sent_bytes.mean()],
            name = 'Benign',
            marker={'color':'#054194'},
            opacity=0.75
                )
                ,
                go.Bar(
            x=['Received', 'Sent'],
            y = [mal_df.received_bytes.mean(), mal_df.sent_bytes.mean()],
            name = 'Malicious',
            marker={'color':'#f97cce'},
            opacity=0.75
                )],
        'layout': go.Layout(
        title='<b>Average of Bytes per Type</b>',
        margin={'l': 70, 'b': 60, 't': 50, 'r': 0},
        height=450)
        }

@app.callback(
    Output(component_id='hist_bytes_received', component_property='figure'), 
    [Input(component_id='client_dropdown', component_property='value')]
    )
def update_graph5(clients):
    if clients == 'All':
        sub_df = full_data
    else:
        sub_df = full_data[full_data['client'] == int(clients)]
    # sub_df = df_enrich[df_enrich['client'] == clients]
    # sub_df = get_df(df_enrich, clients)
    ben_df = sub_df[sub_df['label'] == 'benign']
    mal_df = sub_df[sub_df['label'] == 'malicious']
    
    return {
        'data': [go.Histogram(
            x=ben_df.received_bytes,
            histnorm='percent',
            name = 'Benign',
            marker={'color':'#054194'},
            opacity=0.75
                )
                ,
                go.Histogram(
            x=mal_df.received_bytes,
            histnorm='percent',
            name = 'Malicious',
            marker={'color':'#f97cce'},
            opacity=0.75
                )]
        ,
        'layout': go.Layout(
            title='<b>Distribution of Received Bytes</b>',
            xaxis={'title': 'Bytes' },
            yaxis={'title': 'Count'},
            margin={'l': 70, 'b': 60, 't': 50, 'r': 0},
            height=550,
            bargap=0.2,
            bargroupgap=0.1,
            barmode='overlay'
        )
            }

@app.callback(
    Output(component_id='hist_bytes_sent', component_property='figure'), 
    [Input(component_id='client_dropdown', component_property='value')]
    )
def update_graph6(clients):
    # sub_df = df_enrich[df_enrich['client'] == clients]
    # sub_df = get_df(df_enrich, clients)
    if clients == 'All':
        sub_df = full_data
    else:
        sub_df = full_data[full_data['client'] == int(clients)]
    ben_df = sub_df[sub_df['label'] == 'benign']
    mal_df = sub_df[sub_df['label'] == 'malicious']
    
    return {
        'data': [go.Histogram(
            x=ben_df.sent_bytes,
            histnorm='percent',
            name = 'Benign',
            marker={'color':'#054194'},
            opacity=0.75
                )
                ,
                go.Histogram(
            x=mal_df.sent_bytes,
            histnorm='percent',
            name = 'Malicious',
            marker={'color':'#f97cce'},
            opacity=0.75
                )]
        ,
        'layout': go.Layout(
            title='<b>Distribution of Sent Bytes</b>',
            xaxis={'title': 'Bytes' },
            yaxis={'title': 'Count'},
            margin={'l': 70, 'b': 60, 't': 50, 'r': 0},
            height=550,
            bargap=0.2,
            bargroupgap=0.1,
            barmode='overlay'
        )
    }

if __name__ == '__main__':
    app.run_server(debug=True)


           