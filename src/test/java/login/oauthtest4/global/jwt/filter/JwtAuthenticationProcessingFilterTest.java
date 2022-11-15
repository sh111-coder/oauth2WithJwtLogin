package login.oauthtest4.global.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import login.oauthtest4.domain.user.Role;
import login.oauthtest4.domain.user.User;
import login.oauthtest4.domain.user.repository.UserRepository;
import login.oauthtest4.global.jwt.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import javax.persistence.EntityManager;
import javax.transaction.Transactional;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@Slf4j
class JwtAuthenticationProcessingFilterTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    UserRepository userRepository;

    @Autowired
    EntityManager em;

    @Autowired
    JwtService jwtService;

    private ObjectMapper objectMapper = new ObjectMapper();

    PasswordEncoder delegatingPasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private static final String KEY_EMAIL = "email";
    private static final String KEY_PASSWORD = "password";
    private static final String EMAIL = "test1@naver.com";
    private static final String PASSWORD = "password1";
    private static final String LOGIN_URL = "/login";
    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String BEARER = "Bearer ";

    /**
     * 매 테스트 시작 전에 유저 데이터 생성
     */
    @BeforeEach
    private void init() {
        userRepository.save(User.builder().email(EMAIL).password(delegatingPasswordEncoder.encode(PASSWORD))
                .nickname("KSH1").role(Role.USER).age(25).city("busan").build());
        clear();
    }

    private void clear() {
        em.flush();
        em.clear();
    }

    /**
     * Key : email, password인 usernamePasswordMap 반환
     */
    private Map<String, String> getUsernamePasswordMap(String email, String password) {
        Map<String, String> usernamePasswordMap = new LinkedHashMap<>();
        usernamePasswordMap.put(KEY_EMAIL, email);
        usernamePasswordMap.put(KEY_PASSWORD, password);
        return usernamePasswordMap;
    }

    /**
     * 로그인 요청을 보내서 액세스 토큰, 리프레시 토큰을 Map에 담아 반환
     */
    private Map<String, String> getTokenMap() throws Exception {
        Map<String, String> usernamePasswordMap = getUsernamePasswordMap(EMAIL, PASSWORD);

        // POST "/login", application/json, content로 이메일, 패스워드 Map 요청 결과 반환
        MvcResult result = mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(usernamePasswordMap)))
                .andReturn();

        String accessToken = result.getResponse().getHeader(accessHeader);
        String refreshToken = result.getResponse().getHeader(refreshHeader);

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put(accessHeader, accessToken);
        tokenMap.put(refreshHeader, refreshToken);
        return tokenMap;
    }

    @Test
    @DisplayName("AccessToken, RefreshToken 모두 존재하지 않는 경우 - /login로 302 리다이렉트")
    void Access_Refresh_not_exist() throws Exception {
        // when, then
        mockMvc.perform(get(LOGIN_URL + "123")) // "/login"이 아닌 임의의 주소를 보내기
                .andExpect(status().isFound()); // 헤더에 아무 토큰도 없이 요청하므로 302
    }

    @Test
    @DisplayName("AccessToken 유효, RefreshToken 존재하지 않는 경우 - 인증 성공(없는 주소 404)")
    void Access_valid_and_Refresh_not_exist() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);

        // when, then
        mockMvc.perform(get(LOGIN_URL + "123") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken))
                .andExpect(status().isNotFound()); // 헤더에 아무 토큰도 없이 요청하므로 302
    }

    @Test
    @DisplayName("AccessToken 존재하지만 유효하지 않고, RefreshToken 존재하지 않는 경우 - /login로 302 리다이렉트)")
    void Access_not_valid_and_Refresh_not_exist() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);

        // when, then
        mockMvc.perform(get(LOGIN_URL + "123") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken + "1")) // 틀린 액세스 토큰 보내기
                .andExpect(status().isFound()); // 틀린 액세스 토큰이므로 Forbidden
    }

    @Test
    @DisplayName("AccessToken 존재하지 않고, RefreshToken 유효한 경우 - AccessToken 재발급 후 200")
    void Access_not_exist_and_Refresh_valid() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        MvcResult result = mockMvc.perform(get("/jwt-test1") // "/login"이 아닌 임의의 주소를 보내기
                        .header(refreshHeader, BEARER + refreshToken))
                .andExpect(status().isOk()).andReturn();
        String accessToken = result.getResponse().getHeader(accessHeader);
        String subject = JWT.require(Algorithm.HMAC512(secretKey)).build().verify(accessToken).getSubject();

        assertThat(subject).isEqualTo(ACCESS_TOKEN_SUBJECT);
    }

    @Test
    @DisplayName("AccessToken 존재하지 않고, RefreshToken 유효하지 않은 경우 - /login로 302 리다이렉트")
    void Access_not_exist_and_Refresh_not_valid() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        mockMvc.perform(get("/jwt-test1") // "/login"이 아닌 임의의 주소를 보내기
                        .header(refreshHeader, BEARER + refreshToken + "1")) // 유효하지 않은 리프레시 토큰 보내기
                .andExpect(status().isFound());
    }

    @Test
    @DisplayName("AccessToken 유효, RefreshToken 유효한 경우 - AccessToken 재발급 후 200")
    void Access_valid_and_Refresh_valid() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        MvcResult result = mockMvc.perform(get("/jwt-test1") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken) // 유효한 액세스 토큰 보내기
                        .header(refreshHeader, BEARER + refreshToken)) // 유효한 리프레시 토큰 보내기
                .andExpect(status().isOk()).andReturn();

        String reIssuedAccessToken = result.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result.getResponse().getHeader(refreshHeader);
        String subject = JWT.require(Algorithm.HMAC512(secretKey)).build().verify(reIssuedAccessToken).getSubject();

        assertThat(subject).isEqualTo(ACCESS_TOKEN_SUBJECT);
        assertThat(responseRefreshToken).isNull(); // refreshToken은 재발급 되지 않음
    }

    @Test
    @DisplayName("AccessToken 유효하지 않고, RefreshToken 유효한 경우 - AccessToken 재발급 후 200")
    void Access_not_valid_and_Refresh_valid() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        MvcResult result = mockMvc.perform(get("/jwt-test1") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken + "1") // 유효하지 않은 액세스 토큰 보내기
                        .header(refreshHeader, BEARER + refreshToken)) // 유효한 리프레시 토큰 보내기
                .andExpect(status().isOk()).andReturn();

        String reIssuedAccessToken = result.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result.getResponse().getHeader(refreshHeader);
        String subject = JWT.require(Algorithm.HMAC512(secretKey)).build().verify(reIssuedAccessToken).getSubject();

        assertThat(subject).isEqualTo(ACCESS_TOKEN_SUBJECT);
        assertThat(responseRefreshToken).isNull(); // refreshToken은 재발급 되지 않음
    }

    @Test
    @DisplayName("AccessToken 유효, RefreshToken 유효하지 않은 경우 - 인증 성공, 틀린 주소이므로 404")
    void Access_valid_and_Refresh_not_valid_not_Found_URL() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        MvcResult result = mockMvc.perform(get("/jwt-test1") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken) // 유효한 액세스 토큰 보내기
                        .header(refreshHeader, BEARER + refreshToken + "1")) // 유효하지 않은 리프레시 토큰 보내기
                .andExpect(status().isNotFound()).andReturn();

        String responseAccessToken = result.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result.getResponse().getHeader(refreshHeader);

        assertThat(responseAccessToken).isNull();
        assertThat(responseRefreshToken).isNull();
    }

    @Test
    @DisplayName("AccessToken 유효, RefreshToken 유효하지 않은 경우 - 인증 성공, 있는 주소이므로 200")
    void Access_valid_and_Refresh_not_valid_correct_URL() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        MvcResult result = mockMvc.perform(get("/jwt-test") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken) // 유효한 액세스 토큰 보내기
                        .header(refreshHeader, BEARER + refreshToken + "1")) // 유효하지 않은 리프레시 토큰 보내기
                .andExpect(status().isOk()).andReturn();

        String responseAccessToken = result.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result.getResponse().getHeader(refreshHeader);

        assertThat(responseAccessToken).isNull();
        assertThat(responseRefreshToken).isNull();
    }

    @Test
    @DisplayName("AccessToken 유효하지 않고, RefreshToken 유효하지 않은 경우 - /login로 302 리다이렉트")
    void Access_not_valid_and_Refresh_not_valid() throws Exception {
        // given
        Map<String, String> tokenMap = getTokenMap();
        String accessToken = tokenMap.get(accessHeader);
        String refreshToken = tokenMap.get(refreshHeader);

        // when, then
        mockMvc.perform(get("/jwt-test") // "/login"이 아닌 임의의 주소를 보내기
                        .header(accessHeader, BEARER + accessToken + "1") // 유효하지 않은 액세스 토큰 보내기
                        .header(refreshHeader, BEARER + refreshToken + "1")) // 유효하지 않은 리프레시 토큰 보내기
                .andExpect(status().isFound());
    }

    @Test
    @DisplayName("POST /login으로 요청 보내면 JWT 필터 작동 X")
    void Login_URL_not_Run_jwt_Filter() throws Exception {
        // when, then
        mockMvc.perform(post("/login")) // "/login"이 아닌 임의의 주소를 보내기
                // JwtAuthenticationProcessingFilter에서 Post /login은 다음 필터로 넘겼으므로,
                // 다음 필터인 CustomJsonUsernamePasswordAuthenticationFilter로 넘어가서
                // 필터가 요구하는 JSON 형식이 아니어서 인증 실패 -> LoginFailureHandler로 넘어가서 400 반환
                .andExpect(status().isBadRequest());
    }
}