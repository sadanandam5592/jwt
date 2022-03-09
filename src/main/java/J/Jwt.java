package J;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class Jwt {
    public String key="xcfpfCvp9iIHnD8wBdOADxhY6LdR8NCpN/zoDdTWg6w=";
  public String k(){

      return Jwts.builder().setPayload(String.valueOf(new Date(System.currentTimeMillis())))
              .setPayload(String.valueOf(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))).setPayload("176843").
              signWith(SignatureAlgorithm.HS256,key).compact();
  }

    public static void main(String[] args) {
        Jwt jwt=new Jwt();
        System.out.println(jwt.k());
    }
}
