#!/usr/bin/env python3
"""
Nigerian Roads Database - Comprehensive road network data
Provides AI-powered road risk assessment and location intelligence
"""

import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import sqlite3

# Nigerian States and their Local Government Areas
NIGERIAN_STATES = {
    "Abia": [
        "Aba North", "Aba South", "Arochukwu", "Bende", "Ikwuano", "Isiala Ngwa North", 
        "Isiala Ngwa South", "Isuikwuato", "Obi Ngwa", "Ohafia", "Osisioma", "Ugwunagbo", 
        "Ukwa East", "Ukwa West", "Umuahia North", "Umuahia South", "Umu Nneochi"
    ],
    "Adamawa": [
        "Demsa", "Fufure", "Ganye", "Gayuk", "Gombi", "Grie", "Hong", "Jada", "Lamurde", 
        "Madagali", "Maiha", "Mayo Belwa", "Michika", "Mubi North", "Mubi South", "Numan", 
        "Shelleng", "Song", "Toungo", "Yola North", "Yola South"
    ],
    "Akwa Ibom": [
        "Abak", "Eastern Obolo", "Eket", "Esit Eket", "Essien Udim", "Etim Ekpo", 
        "Etinan", "Ibeno", "Ibesikpo Asutan", "Ibiono-Ibom", "Ika", "Ikono", "Ikot Abasi", 
        "Ikot Ekpene", "Ini", "Itu", "Mbo", "Mkpat-Enin", "Nsit-Atai", "Nsit-Ibom", 
        "Nsit-Ubium", "Obot Akara", "Okobo", "Onna", "Oron", "Oruk Anam", "Udung-Uko", 
        "Ukanafun", "Uruan", "Urue-Offong/Oruko", "Uyo"
    ],
    "Anambra": [
        "Aguata", "Anambra East", "Anambra West", "Anaocha", "Awka North", "Awka South", 
        "Ayamelum", "Dunukofia", "Ekwusigo", "Idemili North", "Idemili South", "Ihiala", 
        "Njikoka", "Nnewi North", "Nnewi South", "Ogbaru", "Onitsha North", "Onitsha South", 
        "Orumba North", "Orumba South", "Oyi"
    ],
    "Bauchi": [
        "Alkaleri", "Bauchi", "Bogoro", "Damban", "Darazo", "Dass", "Gamawa", "Ganjuwa", 
        "Giade", "Itas/Gadau", "Jama'are", "Katagum", "Kirfi", "Misau", "Ningi", "Shira", 
        "Tafawa Balewa", "Toro", "Warji", "Zaki"
    ],
    "Bayelsa": [
        "Brass", "Ekeremor", "Kolokuma/Opokuma", "Nembe", "Ogbia", "Sagbama", "Southern Ijaw", "Yenagoa"
    ],
    "Benue": [
        "Ado", "Agatu", "Apa", "Buruku", "Gboko", "Guma", "Gwer East", "Gwer West", 
        "Katsina-Ala", "Konshisha", "Kwande", "Logo", "Makurdi", "Obi", "Ogbadibo", 
        "Ohimini", "Oju", "Okpokwu", "Oturkpo", "Tarka", "Ukum", "Ushongo", "Vandeikya"
    ],
    "Borno": [
        "Abadam", "Askira/Uba", "Bama", "Bayo", "Biu", "Chibok", "Damboa", "Dikwa", 
        "Gubio", "Guzamala", "Gwoza", "Hawul", "Jere", "Kaga", "Kala/Balge", "Konduga", 
        "Kukawa", "Kwaya Kusar", "Mafa", "Magumeri", "Maiduguri", "Marte", "Mobbar", 
        "Monguno", "Ngala", "Nganzai", "Shani"
    ],
    "Cross River": [
        "Abi", "Akamkpa", "Akpabuyo", "Bakassi", "Bekwarra", "Biase", "Boki", "Calabar Municipal", 
        "Calabar South", "Etung", "Ikom", "Obanliku", "Obubra", "Obudu", "Odukpani", 
        "Ogoja", "Yakuur", "Yala"
    ],
    "Delta": [
        "Aniocha North", "Aniocha South", "Bomadi", "Burutu", "Ethiope East", "Ethiope West", 
        "Ika North East", "Ika South", "Isoko North", "Isoko South", "Ndokwa East", 
        "Ndokwa West", "Okpe", "Oshimili North", "Oshimili South", "Patani", "Sapele", 
        "Udu", "Ughelli North", "Ughelli South", "Ukwuani", "Uvwie", "Warri North", 
        "Warri South", "Warri South West"
    ],
    "Ebonyi": [
        "Abakaliki", "Afikpo North", "Afikpo South", "Ebonyi", "Ezza North", "Ezza South", 
        "Ikwo", "Ishielu", "Ivo", "Izzi", "Ohaozara", "Ohaukwu", "Onicha"
    ],
    "Edo": [
        "Akoko-Edo", "Egor", "Esan Central", "Esan North-East", "Esan South-East", 
        "Esan West", "Etsako Central", "Etsako East", "Etsako West", "Igueben", "Ikpoba Okha", 
        "Oredo", "Orhionmwon", "Ovia North-East", "Ovia South-West", "Owan East", "Owan West", "Uhunmwonde"
    ],
    "Ekiti": [
        "Ado Ekiti", "Efon", "Ekiti East", "Ekiti South-West", "Ekiti West", "Emure", 
        "Gbonyin", "Ido Osi", "Ijero", "Ikere", "Ikole", "Ilejemeje", "Irepodun/Ifelodun", 
        "Ise/Orun", "Moba", "Oye"
    ],
    "Enugu": [
        "Aninri", "Awgu", "Enugu East", "Enugu North", "Enugu South", "Ezeagu", "Igbo Etiti", 
        "Igbo Eze North", "Igbo Eze South", "Isi Uzo", "Nkanu East", "Nkanu West", 
        "Nsukka", "Oji River", "Udenu", "Udi", "Uzo Uwani"
    ],
    "FCT": [
        "Abaji", "Abuja Municipal", "Gwagwalada", "Kuje", "Kwali", "Kwali"
    ],
    "Gombe": [
        "Akko", "Balanga", "Billiri", "Dukku", "Funakaye", "Gombe", "Kaltungo", "Kwami", 
        "Nafada", "Shongom", "Yamaltu/Deba"
    ],
    "Imo": [
        "Aboh Mbaise", "Ahiazu Mbaise", "Ehime Mbano", "Ezinihitte", "Ideato North", 
        "Ideato South", "Ihitte/Uboma", "Ikeduru", "Isiala Mbano", "Isu", "Mbaitoli", 
        "Ngor Okpala", "Njaba", "Nkwerre", "Nwangele", "Obowo", "Oguta", "Ohaji/Egbema", 
        "Okigwe", "Orlu", "Orsu", "Oru East", "Oru West", "Owerri Municipal", "Owerri North", "Owerri West", "Unuimo"
    ],
    "Jigawa": [
        "Auyo", "Babura", "Biriniwa", "Birnin Kudu", "Buji", "Dutse", "Gagarawa", "Garki", 
        "Gumel", "Guri", "Gwaram", "Gwiwa", "Hadejia", "Jahun", "Kafin Hausa", "Kaugama", 
        "Kazaure", "Kiri Kasama", "Kiyawa", "Maigatari", "Malam Madori", "Miga", "Ringim", 
        "Roni", "Sule Tankarkar", "Taura", "Yankwashi"
    ],
    "Kaduna": [
        "Birnin Gwari", "Chikun", "Giwa", "Igabi", "Ikara", "Jaba", "Jema'a", "Kachia", 
        "Kaduna North", "Kaduna South", "Kagarko", "Kajuru", "Kaura", "Kauru", "Kubau", 
        "Kudan", "Lere", "Makarfi", "Sabon Gari", "Sanga", "Soba", "Zangon Kataf", "Zaria"
    ],
    "Kano": [
        "Ajingi", "Albasu", "Bagwai", "Bebeji", "Bichi", "Bunkure", "Dala", "Dambatta", 
        "Dawakin Kudu", "Dawakin Tofa", "Doguwa", "Fagge", "Gabasawa", "Garko", "Garum", 
        "Mallam", "Gaya", "Gezawa", "Gwale", "Gwarzo", "Kabo", "Kano Municipal", 
        "Karaye", "Kibiya", "Kiru", "Kumbotso", "Kunchi", "Kura", "Madobi", "Makoda", 
        "Minjibir", "Nasarawa", "Rano", "Rimin Gado", "Rogo", "Shanono", "Sumaila", 
        "Takai", "Tarauni", "Tofa", "Tsanyawa", "Tudun Wada", "Ungogo", "Warawa", "Wudil"
    ],
    "Katsina": [
        "Bakori", "Batagarawa", "Batsari", "Baure", "Bindawa", "Charanchi", "Dandume", 
        "Danja", "Dan Musa", "Daura", "Dutsi", "Dutsin Ma", "Faskari", "Funtua", "Ingawa", 
        "Jibia", "Kafur", "Kaita", "Kankara", "Kankia", "Katsina", "Kurfi", "Kusada", 
        "Mai'Adua", "Malumfashi", "Mani", "Mashi", "Matazu", "Musawa", "Rimi", "Sabuwa", 
        "Safana", "Sandamu", "Zango"
    ],
    "Kebbi": [
        "Aleiro", "Arewa Dandi", "Argungu", "Augie", "Bagudo", "Birnin Kebbi", "Bunza", 
        "Dandi", "Fakai", "Gwandu", "Jega", "Kalgo", "Koko/Besse", "Maiyama", "Ngaski", 
        "Sakaba", "Shanga", "Suru", "Wasagu/Danko", "Yauri", "Zuru"
    ],
    "Kogi": [
        "Adavi", "Ajaokuta", "Ankpa", "Bassa", "Dekina", "Ibaji", "Idah", "Igalamela Odolu", 
        "Ijumu", "Kabba/Bunu", "Kogi", "Lokoja", "Mopa Muro", "Ofu", "Ogori/Magongo", 
        "Okehi", "Okene", "Olamaboro", "Omala", "Yagba East", "Yagba West"
    ],
    "Kwara": [
        "Asa", "Baruten", "Edu", "Ekiti", "Ifelodun", "Ilorin East", "Ilorin South", 
        "Ilorin West", "Irepodun", "Isin", "Kaiama", "Moro", "Offa", "Oke Ero", "Oyun", "Pategi"
    ],
    "Lagos": [
        "Agege", "Ajeromi-Ifelodun", "Alimosho", "Amuwo-Odofin", "Apapa", "Badagry", 
        "Epe", "Eti Osa", "Ibeju-Lekki", "Ifako-Ijaiye", "Ikeja", "Ikorodu", "Kosofe", 
        "Lagos Island", "Lagos Mainland", "Mushin", "Ojo", "Oshodi-Isolo", "Shomolu", "Surulere"
    ],
    "Nasarawa": [
        "Akwanga", "Awe", "Doma", "Karu", "Keana", "Keffi", "Kokona", "Lafia", "Nasarawa", 
        "Nasarawa Egon", "Obi", "Toto", "Wamba"
    ],
    "Niger": [
        "Agaie", "Agwara", "Bida", "Borgu", "Bosso", "Chanchaga", "Edati", "Gbako", 
        "Gurara", "Katcha", "Kontagora", "Lapai", "Lavun", "Magama", "Mariga", "Mashegu", 
        "Mokwa", "Moya", "Paikoro", "Rafi", "Rijau", "Shiroro", "Suleja", "Tafa", "Wushishi"
    ],
    "Ogun": [
        "Abeokuta North", "Abeokuta South", "Ado-Odo/Ota", "Egbado North", "Egbado South", 
        "Ewekoro", "Ifo", "Ijebu East", "Ijebu North", "Ijebu North East", "Ijebu Ode", 
        "Ikenne", "Imeko Afon", "Ipokia", "Obafemi Owode", "Odeda", "Odogbolu", "Ogun Waterside", "Remo North", "Sagamu", "Yewa North", "Yewa South"
    ],
    "Ondo": [
        "Akoko North-East", "Akoko North-West", "Akoko South-East", "Akoko South-West", 
        "Akure North", "Akure South", "Ese Odo", "Idanre", "Ifedore", "Ilaje", "Ile Oluji/Okeigbo", 
        "Irele", "Odigbo", "Okitipupa", "Ondo East", "Ondo West", "Ose", "Owo"
    ],
    "Osun": [
        "Aiyedade", "Aiyedire", "Atakunmosa East", "Atakunmosa West", "Boluwaduro", 
        "Boripe", "Ede North", "Ede South", "Egbedore", "Ejigbo", "Ife Central", 
        "Ife East", "Ife North", "Ife South", "Ifedayo", "Ifelodun", "Ila", "Ilesa East", 
        "Ilesa West", "Irepodun", "Irewole", "Isokan", "Iwo", "Obokun", "Odo Otin", 
        "Ola Oluwa", "Olorunda", "Oriade", "Orolu", "Osogbo"
    ],
    "Oyo": [
        "Afijio", "Akinyele", "Atiba", "Atisbo", "Egbeda", "Ibadan North", "Ibadan North-East", 
        "Ibadan North-West", "Ibadan South-East", "Ibadan South-West", "Ibarapa Central", 
        "Ibarapa East", "Ibarapa North", "Ido", "Irepo", "Iseyin", "Itesiwaju", "Iwajowa", 
        "Kajola", "Lagelu", "Ogbomosho North", "Ogbomosho South", "Ogo Oluwa", "Olorunsogo", 
        "Oluyole", "Ona Ara", "Orelope", "Ori Ire", "Oyo East", "Oyo West", "Saki East", 
        "Saki West", "Surulere"
    ],
    "Plateau": [
        "Barkin Ladi", "Bassa", "Bokkos", "Jos East", "Jos North", "Jos South", "Kanam", 
        "Kanke", "Langtang North", "Langtang South", "Mangu", "Mikang", "Pankshin", 
        "Qua'an Pan", "Riyom", "Shendam", "Wase"
    ],
    "Rivers": [
        "Abua/Odual", "Ahoada East", "Ahoada West", "Akuku-Toru", "Andoni", "Asari-Toru", 
        "Bonny", "Degema", "Eleme", "Emohua", "Etche", "Gokana", "Ikwerre", "Khana", 
        "Obio/Akpor", "Ogba/Egbema/Ndoni", "Ogu/Bolo", "Okrika", "Omuma", "Opobo/Nkoro", "Oyigbo", "Port Harcourt", "Tai"
    ],
    "Sokoto": [
        "Binji", "Bodinga", "Dange Shuni", "Gada", "Goronyo", "Gudu", "Gwadabawa", 
        "Illela", "Isa", "Kebbe", "Kware", "Rabah", "Sabon Birni", "Shagari", "Silame", 
        "Sokoto North", "Sokoto South", "Tambuwal", "Tangaza", "Tureta", "Wamako", "Wurno", "Yabo"
    ],
    "Taraba": [
        "Ardo Kola", "Bali", "Donga", "Gashaka", "Gassol", "Ibi", "Jalingo", "Karim Lamido", 
        "Kurmi", "Lau", "Sardauna", "Takum", "Ussa", "Wukari", "Yorro", "Zing"
    ],
    "Yobe": [
        "Bade", "Bursari", "Damaturu", "Fika", "Fune", "Geidam", "Gujba", "Gulani", 
        "Jakusko", "Karasuwa", "Machina", "Nangere", "Nguru", "Potiskum", "Tarmuwa", "Yunusari", "Yusufari"
    ],
    "Zamfara": [
        "Anka", "Bakura", "Birnin Magaji/Kiyaw", "Bukkuyum", "Bungudu", "Gummi", "Gusau", 
        "Kaura Namoda", "Maradun", "Maru", "Shinkafi", "Talata Mafara", "Tsafe", "Zurmi"
    ]
}

# Major Nigerian Highways and Roads
MAJOR_ROADS = {
    "A1": {
        "name": "Lagos-Ibadan Expressway",
        "states": ["Lagos", "Ogun", "Oyo"],
        "length_km": 127,
        "type": "Expressway",
        "status": "Under Construction",
        "risk_factors": ["Heavy Traffic", "Construction Zones", "Accidents"]
    },
    "A2": {
        "name": "Ibadan-Ife Expressway",
        "states": ["Oyo", "Osun"],
        "length_km": 55,
        "type": "Expressway",
        "status": "Good",
        "risk_factors": ["Heavy Traffic", "Sharp Curves"]
    },
    "A3": {
        "name": "Lagos-Abeokuta Expressway",
        "states": ["Lagos", "Ogun"],
        "length_km": 78,
        "type": "Expressway",
        "status": "Fair",
        "risk_factors": ["Potholes", "Heavy Traffic"]
    },
    "A4": {
        "name": "Enugu-Onitsha Expressway",
        "states": ["Enugu", "Anambra"],
        "length_km": 110,
        "type": "Expressway",
        "status": "Good",
        "risk_factors": ["Heavy Traffic", "Sharp Curves"]
    },
    "A5": {
        "name": "Kano-Kaduna Expressway",
        "states": ["Kano", "Kaduna"],
        "length_km": 200,
        "type": "Expressway",
        "status": "Good",
        "risk_factors": ["Banditry", "Poor Lighting"]
    },
    "A6": {
        "name": "Port Harcourt-Aba Expressway",
        "states": ["Rivers", "Abia"],
        "length_km": 65,
        "type": "Expressway",
        "status": "Poor",
        "risk_factors": ["Potholes", "Heavy Traffic", "Flooding"]
    },
    "A7": {
        "name": "Calabar-Itu Highway",
        "states": ["Cross River", "Akwa Ibom"],
        "length_km": 85,
        "type": "Highway",
        "status": "Fair",
        "risk_factors": ["Sharp Curves", "Poor Drainage"]
    },
    "A8": {
        "name": "Maiduguri-Damaturu Highway",
        "states": ["Borno", "Yobe"],
        "length_km": 130,
        "type": "Highway",
        "status": "Poor",
        "risk_factors": ["Insurgency", "Poor Road Condition"]
    },
    "A9": {
        "name": "Lokoja-Abuja Highway",
        "states": ["Kogi", "FCT"],
        "length_km": 160,
        "type": "Highway",
        "status": "Good",
        "risk_factors": ["Heavy Traffic", "Sharp Curves"]
    },
    "A10": {
        "name": "Kano-Maiduguri Highway",
        "states": ["Kano", "Jigawa", "Bauchi", "Gombe", "Borno"],
        "length_km": 450,
        "type": "Highway",
        "status": "Fair",
        "risk_factors": ["Insurgency", "Poor Road Condition", "Banditry"]
    }
}

# Road Risk Categories
ROAD_RISK_CATEGORIES = {
    "Traffic": {
        "description": "Traffic-related incidents",
        "subcategories": ["Heavy Traffic", "Traffic Jam", "Accident", "Road Rage"]
    },
    "Infrastructure": {
        "description": "Road infrastructure issues",
        "subcategories": ["Potholes", "Road Damage", "Bridge Issues", "Drainage Problems"]
    },
    "Security": {
        "description": "Security-related incidents",
        "subcategories": ["Robbery", "Kidnapping", "Banditry", "Protest", "Civil Unrest"]
    },
    "Environmental": {
        "description": "Environmental factors",
        "subcategories": ["Flooding", "Landslide", "Erosion", "Weather Conditions"]
    },
    "Construction": {
        "description": "Construction-related issues",
        "subcategories": ["Construction Zone", "Road Work", "Diversion", "Equipment"]
    }
}

class NigerianRoadsDatabase:
    """Comprehensive Nigerian roads database with AI-powered risk assessment"""
    
    def __init__(self):
        self.states = NIGERIAN_STATES
        self.major_roads = MAJOR_ROADS
        self.risk_categories = ROAD_RISK_CATEGORIES
        self.init_database()
    
    def init_database(self):
        """Initialize the roads database"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            # Create states table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS states (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    capital TEXT,
                    region TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create local_governments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS local_governments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    state_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (state_id) REFERENCES states (id)
                )
            ''')
            
            # Create major_roads table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS major_roads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    road_code TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    states TEXT,
                    length_km REAL,
                    road_type TEXT,
                    status TEXT,
                    risk_factors TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create road_risks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS road_risks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    road_id INTEGER,
                    risk_type TEXT NOT NULL,
                    risk_subtype TEXT,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    location_lat REAL,
                    location_lng REAL,
                    local_government TEXT,
                    state TEXT,
                    reported_by INTEGER,
                    status TEXT DEFAULT 'active',
                    confirmations INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (road_id) REFERENCES major_roads (id),
                    FOREIGN KEY (reported_by) REFERENCES users (id)
                )
            ''')
            
            # Create road_conditions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS road_conditions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    road_id INTEGER,
                    condition_type TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    location_lat REAL,
                    location_lng REAL,
                    local_government TEXT,
                    state TEXT,
                    reported_by INTEGER,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (road_id) REFERENCES major_roads (id),
                    FOREIGN KEY (reported_by) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
            # Populate with initial data
            self.populate_initial_data()
            
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def populate_initial_data(self):
        """Populate database with initial Nigerian roads data"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            # Insert states
            for state_name in self.states.keys():
                cursor.execute('''
                    INSERT OR IGNORE INTO states (name) VALUES (?)
                ''', (state_name,))
            
            # Insert local governments
            for state_name, lgas in self.states.items():
                cursor.execute('SELECT id FROM states WHERE name = ?', (state_name,))
                state_id = cursor.fetchone()[0]
                
                for lga in lgas:
                    cursor.execute('''
                        INSERT OR IGNORE INTO local_governments (name, state_id) VALUES (?, ?)
                    ''', (lga, state_id))
            
            # Insert major roads
            for road_code, road_data in self.major_roads.items():
                cursor.execute('''
                    INSERT OR IGNORE INTO major_roads 
                    (road_code, name, states, length_km, road_type, status, risk_factors)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    road_code,
                    road_data['name'],
                    json.dumps(road_data['states']),
                    road_data['length_km'],
                    road_data['type'],
                    road_data['status'],
                    json.dumps(road_data['risk_factors'])
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Data population error: {e}")
    
    def get_states(self) -> List[str]:
        """Get all Nigerian states"""
        return list(self.states.keys())
    
    def get_local_governments(self, state: str) -> List[str]:
        """Get local governments for a specific state"""
        return self.states.get(state, [])
    
    def get_major_roads(self, state: str = None) -> List[Dict]:
        """Get major roads, optionally filtered by state"""
        if state:
            return {k: v for k, v in self.major_roads.items() if state in v['states']}
        return self.major_roads
    
    def get_road_by_name(self, road_name: str) -> Optional[Dict]:
        """Get road information by name"""
        for road_code, road_data in self.major_roads.items():
            if road_name.lower() in road_data['name'].lower():
                return {**road_data, 'code': road_code}
        return None
    
    def get_risk_categories(self) -> Dict:
        """Get all risk categories and subcategories"""
        return self.risk_categories
    
    def add_road_risk(self, risk_data: Dict) -> bool:
        """Add a new road risk report"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO road_risks 
                (road_id, risk_type, risk_subtype, description, severity, 
                 location_lat, location_lng, local_government, state, reported_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                risk_data.get('road_id'),
                risk_data.get('risk_type'),
                risk_data.get('risk_subtype'),
                risk_data.get('description'),
                risk_data.get('severity', 'medium'),
                risk_data.get('location_lat'),
                risk_data.get('location_lng'),
                risk_data.get('local_government'),
                risk_data.get('state'),
                risk_data.get('reported_by')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding road risk: {e}")
            return False

    def add_road_condition(self, condition_data: Dict) -> bool:
        """Add a new road condition report"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO road_conditions 
                (road_id, condition_type, description, severity, 
                 location_lat, location_lng, local_government, state, reported_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                condition_data.get('road_id'),
                condition_data.get('condition'),
                condition_data.get('description'),
                condition_data.get('severity', 'medium'),
                condition_data.get('latitude'),
                condition_data.get('longitude'),
                condition_data.get('lga'),
                condition_data.get('state'),
                condition_data.get('reported_by', 'user')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding road condition: {e}")
            return False
    
    def get_road_risks(self, hours: int = 24, state: str = None, road_id: int = None) -> List[Dict]:
        """Get road risks for the specified time period"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            query = '''
                SELECT rr.*, mr.name as road_name, mr.road_code
                FROM road_risks rr
                LEFT JOIN major_roads mr ON rr.road_id = mr.id
                WHERE rr.created_at >= datetime('now', '-{} hours')
            '''.format(hours)
            
            params = []
            if state:
                query += " AND rr.state = ?"
                params.append(state)
            
            if road_id:
                query += " AND rr.road_id = ?"
                params.append(road_id)
            
            query += " ORDER BY rr.created_at DESC"
            
            cursor.execute(query, params)
            risks = cursor.fetchall()
            
            conn.close()
            
            # Convert to list of dictionaries
            risk_list = []
            for risk in risks:
                risk_list.append({
                    'id': risk[0],
                    'road_id': risk[1],
                    'risk_type': risk[2],
                    'risk_subtype': risk[3],
                    'description': risk[4],
                    'severity': risk[5],
                    'location_lat': risk[6],
                    'location_lng': risk[7],
                    'local_government': risk[8],
                    'state': risk[9],
                    'reported_by': risk[10],
                    'status': risk[11],
                    'confirmations': risk[12],
                    'created_at': risk[13],
                    'updated_at': risk[14],
                    'road_name': risk[15],
                    'road_code': risk[16]
                })
            
            return risk_list
            
        except Exception as e:
            print(f"Error getting road risks: {e}")
            return []
    
    def get_road_conditions(self, months: int = 3, state: str = None) -> List[Dict]:
        """Get road conditions for the specified time period"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            query = '''
                SELECT rc.*, mr.name as road_name, mr.road_code
                FROM road_conditions rc
                LEFT JOIN major_roads mr ON rc.road_id = mr.id
                WHERE rc.created_at >= datetime('now', '-{} months')
            '''.format(months)
            
            params = []
            if state:
                query += " AND rc.state = ?"
                params.append(state)
            
            query += " ORDER BY rc.created_at DESC"
            
            cursor.execute(query, params)
            conditions = cursor.fetchall()
            
            conn.close()
            
            # Convert to list of dictionaries
            condition_list = []
            for condition in conditions:
                condition_list.append({
                    'id': condition[0],
                    'road_id': condition[1],
                    'condition_type': condition[2],
                    'description': condition[3],
                    'severity': condition[4],
                    'location_lat': condition[5],
                    'location_lng': condition[6],
                    'local_government': condition[7],
                    'state': condition[8],
                    'reported_by': condition[9],
                    'status': condition[10],
                    'created_at': condition[11],
                    'road_name': condition[12],
                    'road_code': condition[13]
                })
            
            return condition_list
            
        except Exception as e:
            print(f"Error getting road conditions: {e}")
            return []
    
    def get_road_statistics(self, state: str = None) -> Dict:
        """Get road statistics and analytics"""
        try:
            conn = sqlite3.connect('nigerian_roads.db')
            cursor = conn.cursor()
            
            # Get total risks in last 24 hours
            cursor.execute('''
                SELECT COUNT(*) FROM road_risks 
                WHERE created_at >= datetime('now', '-24 hours')
            ''')
            risks_24h = cursor.fetchone()[0]
            
            # Get total risks in last 7 days
            cursor.execute('''
                SELECT COUNT(*) FROM road_risks 
                WHERE created_at >= datetime('now', '-7 days')
            ''')
            risks_7d = cursor.fetchone()[0]
            
            # Get total conditions in last 3 months
            cursor.execute('''
                SELECT COUNT(*) FROM road_conditions 
                WHERE created_at >= datetime('now', '-3 months')
            ''')
            conditions_3m = cursor.fetchone()[0]
            
            # Get risk types distribution
            cursor.execute('''
                SELECT risk_type, COUNT(*) FROM road_risks 
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY risk_type
            ''')
            risk_types = dict(cursor.fetchall())
            
            # Get states with most risks
            cursor.execute('''
                SELECT state, COUNT(*) FROM road_risks 
                WHERE created_at >= datetime('now', '-7 days')
                GROUP BY state
                ORDER BY COUNT(*) DESC
                LIMIT 5
            ''')
            top_states = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'risks_24h': risks_24h,
                'risks_7d': risks_7d,
                'conditions_3m': conditions_3m,
                'risk_types': risk_types,
                'top_states': top_states
            }
            
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}

# Global instance
nigerian_roads_db = NigerianRoadsDatabase()

if __name__ == "__main__":
    # Test the database
    print("Nigerian Roads Database initialized successfully!")
    print(f"States: {len(nigerian_roads_db.get_states())}")
    print(f"Major Roads: {len(nigerian_roads_db.get_major_roads())}")
    print(f"Risk Categories: {len(nigerian_roads_db.get_risk_categories())}") 