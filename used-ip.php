<!DOCTYPE html>
<html>
<head>
    <title>used IPs</title>
    <style>
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>Used IPs</h1>
    <table>
        <thead>
            <tr>
                <th>IPEndpoint</th>
                <th>Subnet</th>
            </tr>
        </thead>
        <tbody>
            <?php
            // MySQL database connection
            $mysql_host = '127.0.0.1';
            $mysql_username = 'root';
            $mysql_password = 'myadmin1502';
            $mysql_database = 'endpointer';

            $conn = new mysqli($mysql_host, $mysql_username, $mysql_password, $mysql_database);
            if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
            }

            // Query to retrieve the unused IPs grouped by subnet
            $query = "SELECT IPEndpoint, subnet FROM used_ips ;";

            $result = $conn->query($query);
            if ($result) {
                if ($result->num_rows > 0) {
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>";
                        echo "<td>" . $row['IPSubnet'] . "</td>";
                        echo "<td>" . $row['subnet'] . "</td>";
                        echo "</tr>";
                    }
                } else {
                    echo "<tr><td colspan='4'>No unused IPs found.</td></tr>";
                }
            } else {
                echo "Query failed: " . $conn->error;
            }
            
            $conn->close();
            ?>
        </tbody>
    </table>
</body>
</html>
